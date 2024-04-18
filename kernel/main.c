#include "linux/netfilter.h"
#include <linux/netfilter.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

#define MODULE_NAME "switchic"
#define log(level, ftm, ...) printk(level "%s: "ftm"\n", MODULE_NAME, ##__VA_ARGS__);
uint32_t IP = 0;
// ~~~~~ IP filter ~~~~~

// ~~~~~ /dev/little_firewall ~~~~
#define DEVICE_NAME "little_firewall"
static int IsOpen = 0; // Устройство может быть открыто только в одном экземпляре в момент

// Открытие
static int device_lf_on_open(struct inode *inode, struct file *file)
{
    if (IsOpen)
        return -EBUSY;
    
    IsOpen++;
    if(try_module_get(THIS_MODULE))
        return 0;

    return -EIO;
}

// Закрытие
static int device_lf_on_release(struct inode *inode, struct file *file)
{
    IsOpen = 0;
    module_put(THIS_MODULE);
    return 0;
}

// Чтение
static ssize_t device_lf_on_read(struct file *flip, char *buffer, size_t len, loff_t *offset)
{
    size_t readed = 0;
    char *number = kmalloc(256, GFP_KERNEL);
    size_t count = snprintf(number, 256, "%u\n", IP);
    while(readed != len && readed != count)
    {
        if(put_user(number[readed], buffer++))
            return -EIO;
        readed++;
    }

    kfree(number);
    number = NULL;

    return readed;
}

// Запись
static ssize_t device_lf_on_write(struct file *flip, const char *buffer, size_t len, loff_t *offset)
{
    return -EROFS;
}

static dev_t device_lf_major = 0;
struct class *pClass = NULL;
static struct file_operations device_ls_ops = {
    .read = device_lf_on_read,
    .write = device_lf_on_write,
    .open = device_lf_on_open,
    .release = device_lf_on_release
};

// ~~~~~ PacketFilter ~~~~~

#define MAKE_IP(x, y, z, w) htonl((x << 24) | (y << 16) | (z << 8) | w)

static unsigned int packet_hook(void *in, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if(!strcmp(state->in->name, "enp1s0")) // Не трогаем адаптер через который работаем с виртуальной машиной
        return NF_ACCEPT;

    // ip заголовок
    struct iphdr *ip_header = (struct iphdr*) skb_network_header(skb);

    if(!skb) 
        return NF_DROP;

    if(ip_header->protocol != 17) // ! UDP
        return NF_ACCEPT;

    struct udphdr *udp_header = (struct udphdr*) skb_transport_header(skb);
    uint16_t dst_port = ntohs(udp_header->dest);
    if(skb->len <= 28)
        return NF_ACCEPT;

    uint8_t *data = skb->data + 28; // IP + UDP
        
    if(dst_port == 68) // DHCP: Ответ сервера клиенту
    {
        if(data[0] == 2 // DHCPOFFER
            || data[0] == 5// DHCPACK
        )
        {
            data[0] = 0; // Если отмена пакета не влияет на его распространение, то поломаем его
            //kfree_skb(skb);
            //return NF_STOLEN;
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops packet_filter_sct __read_mostly = {
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST,        // Наивысший приоритет (0)
        .hooknum = NF_INET_PRE_ROUTING,     // Очередь в которую изначально попадают пакеты
        .hook = (nf_hookfn *) packet_hook
};

// ~~~~~ init ~~~~~

int next_init_module(void)
{
    log(KERN_INFO, "Модуль загружен");

    int code = register_chrdev(0, DEVICE_NAME, &device_ls_ops);
    if(code < 0)
    {
        log(KERN_ALERT, "Не удалось зарегистрировать устройство %s: %d", DEVICE_NAME, code);
        return -1;
    }

    device_lf_major = MKDEV(code, 0);

    // Создаём класс устройства для автоматического создания символьного устройста в файловой системе (/dev/little_firewall)
    if (IS_ERR(pClass = class_create(THIS_MODULE, DEVICE_NAME))) {
        log(KERN_WARNING, "Не удалось создать класс %s %ld\n", DEVICE_NAME, -(ssize_t) pClass);
        pClass = NULL;
        return -1;
    }

    struct device *pDev;
    // Создаём устройство в папке /dev
    if (IS_ERR(pDev = device_create(pClass, NULL, device_lf_major, NULL, DEVICE_NAME))) {
        log(KERN_WARNING, "Не удалось создать устройство %s %ld", DEVICE_NAME, -(ssize_t) pDev);
        pDev = NULL;
        return -1;
    }

    log(KERN_INFO, "major(%s) = %d", DEVICE_NAME, MAJOR(device_lf_major));

    // Регистрация фильтра пакетов
    if((code = nf_register_net_hook(&init_net, &packet_filter_sct)))
    {
        log(KERN_WARNING, "Не удалось зарегистрировать фильтр пакетов %d", -code);
        return -1;
    }
        
    return 0;
}

void cleanup_module(void)
{
    nf_unregister_net_hook(&init_net, &packet_filter_sct);

    if(pClass && device_lf_major >= 0)
        device_destroy(pClass, device_lf_major);

    if(pClass)
        class_destroy(pClass);

    if(device_lf_major >= 0)
        unregister_chrdev(device_lf_major, DEVICE_NAME);

    log(KERN_INFO, "Модуль выгружен");
}
 
int init_module(void)
{
    int result = next_init_module();
    if(result)
        cleanup_module();

    return result;
}
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kakadu");
MODULE_DESCRIPTION("LittleFirewall");
MODULE_VERSION("0.01");

// insmod rmmod
// mknod /dev/little_firewall c MAJOR 0