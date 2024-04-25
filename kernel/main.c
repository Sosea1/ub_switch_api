#include "linux/netfilter.h"
#include "linux/uaccess.h"
#include "linux/uio.h"
#include "linux/vmalloc.h"
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

// DHCP Snopping devs

struct dhcp_snopping_info {
    char *devs;
    size_t count, size, end;
};

struct dhcp_snop_rewrite {
    struct dhcp_snopping_info info;
    size_t readed;
    bool bad_write;
};

static struct dhcp_snopping_info dhcp_snopping_active = {NULL, 0, 0, 0};

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
    {
        size_t size = sizeof(struct dhcp_snop_rewrite);
        file->private_data = vmalloc(size);

        if(!file->private_data)
            return -EIO;

        memset(file->private_data, 0, size);
        ((struct dhcp_snop_rewrite*) file->private_data)->bad_write = true;
        return 0;
    }

    return -EIO;
}

// Закрытие
static int device_lf_on_release(struct inode *inode, struct file *file)
{
    IsOpen = 0;
    if(file->private_data)
    {
        char *prev = dhcp_snopping_active.devs;
        struct dhcp_snop_rewrite *header = file->private_data;
        struct dhcp_snopping_info *info = &header->info;
        if(header->bad_write)
        {
            if(info->devs)
                vfree(info->devs);
        } else if(!prev)
        {
            dhcp_snopping_active.devs = info->devs;
            dhcp_snopping_active.size = info->size;
            dhcp_snopping_active.end = info->end;
            dhcp_snopping_active.count = info->count;
        } else {
            if(info->count > dhcp_snopping_active.count)
            {
                dhcp_snopping_active.devs = info->devs;
                dhcp_snopping_active.count = info->count;
            } else {
                dhcp_snopping_active.count = info->count;
                dhcp_snopping_active.devs = info->devs;
            }

            dhcp_snopping_active.size = info->size;
            dhcp_snopping_active.end = info->end;

            vfree(prev);
        }

        vfree(file->private_data);
    }

    module_put(THIS_MODULE);
    return 0;
}

// Чтение
static ssize_t device_lf_on_read(struct file *flip, char *buffer, size_t len, loff_t *offset)
{
    struct dhcp_snop_rewrite *info = (struct dhcp_snop_rewrite*) flip->private_data;
    if(info->readed >= dhcp_snopping_active.end)
        return 0;

    size_t how_many = min(len, dhcp_snopping_active.end-info->readed);
    if(copy_to_user(buffer, dhcp_snopping_active.devs+info->readed, how_many))
        return -EIO;

    info->readed += how_many;

    return (ssize_t) how_many;
}

// Запись
static ssize_t device_lf_on_write(struct file *flip, const char *buffer, size_t len, loff_t *offset)
{
    struct dhcp_snop_rewrite *info = flip->private_data;

    if(info->info.end+len < info->info.size || !info->info.devs)
    {
        // Перевыделение памяти
        size_t new_size = (info->info.size >> 1) + info->info.size;

        if(new_size == 0)
        {
            new_size = 128;
            info->bad_write = false;
        }

        char *ptr = vmalloc(new_size);

        if(!ptr)
        {
            info->bad_write = true;
            return -EIO;
        }

        char *from = info->info.devs, *to = ptr;
        for(size_t iter = 0; iter < info->info.end; iter++, from++, to++)
            *to = *from;

        from = info->info.devs;
        info->info.devs = ptr;
        vfree(from);
        info->info.size = new_size;
    }

    if(copy_from_user(info->info.devs+info->info.end, buffer, len))
    {
        info->bad_write = true;
        return -EIO;
    }
    
    char *start = info->info.devs + info->info.end;
    for(size_t iter = 0; iter < len; iter++, start++)
        if(*start == '\0')
            info->info.count++;

    info->info.end += len;

    return len;
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

    // Трогаем адаптеры в списке
    {
        bool finded = false;
        char *begin = dhcp_snopping_active.devs;
        size_t start_size = dhcp_snopping_active.size, offset = 0;

        for(size_t iter = 0; iter < dhcp_snopping_active.count; iter++)
        {
            if(strcmp(begin, state->in->name) == 0)
            {
                finded = true;
                break;
            }

            size_t find_zero = 0;
            for(; find_zero < dhcp_snopping_active.end-offset && *begin != '\0'; find_zero++, begin++);
            if(dhcp_snopping_active.end == (size_t) (begin-dhcp_snopping_active.devs))
                break;

            find_zero++;
            begin++;
            offset += find_zero;

            if(start_size != dhcp_snopping_active.size)
                break;
        }

        if(!finded)
            return NF_ACCEPT;
    }

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