#include <linux/err.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#define CRYPTO_CORE_ADDR	0x8000000
#define CRYPTO_CORE_SIZE	0x200

#define REG_ID		0x0
#define REG_MODE	0x8
#define REG_FORMAT	0x10
#define REG_START	0x18
#define REG_VALID	0x20

#define REG_KEY_0	0x28
#define REG_KEY_1	0x30
#define REG_KEY_2	0x38
#define REG_KEY_3	0x40
#define REG_KEY_4	0x48
#define REG_KEY_5	0x50
#define REG_KEY_6	0x58
#define REG_KEY_7	0x60

#define REG_IV_0	0x68
#define REG_IV_1	0x70
#define REG_IV_2	0x78
#define REG_IV_3	0x80

#define REG_IN_0	0x88
#define REG_IN_1	0x90
#define REG_IN_2	0x98
#define REG_IN_3	0x100

#define REG_OUT_0	0x108
#define REG_OUT_1	0x110
#define REG_OUT_2	0x118
#define REG_OUT_3	0x120

#define REG_KEY_CHAR	0x128
#define REG_IV_CHAR	0x130
#define REG_IN_CHAR	0x138
#define REG_OUT_CHAR	0x140

struct crypto_core
{
	struct device *dev;
	void __iomem *base;
};

static void uint32_to_uint8(const uint32_t input32, uint8_t *outputch)
{
	outputch[3] = (input32 >> 24) & 0xFF;
	outputch[2] = (input32 >> 16) & 0xFF;
	outputch[1] = (input32 >> 8) & 0xFF;
	outputch[0] = input32 & 0xFF;
}

static uint32_t char_to_uint32(const char *inputch)
{
	uint32_t result = 0;
	result |= (uint32_t)inputch[0];
	result |= ((uint32_t)inputch[1] << 8);
	result |= ((uint32_t)inputch[2] << 16);
	result |= ((uint32_t)inputch[3] << 24);

	return result;
}

static ssize_t cc_show(
	struct device *dev, struct device_attribute *attr, char *buf, uint64_t offset
)
{
	struct crypto_core *ct = dev_get_drvdata(dev);
	uint64_t val = readl_relaxed(ct->base + offset);
	return scnprintf(buf, PAGE_SIZE, "%llx\n", val);
}

static ssize_t cc_store(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len, uint64_t offset
)
{
	struct crypto_core *ct = dev_get_drvdata(dev);
	uint64_t val;
	if(kstrtoull(buf, 0, &val))
	{
		return -EINVAL;
	}
	writel(val, ct->base + offset);
	return len;
}

// ID

static ssize_t ct_show_id(
	struct device *dev, struct device_attribute *attr, char *buf
)
{
	return cc_show(dev, attr, buf, REG_ID);
}

// FORMAT

static ssize_t ct_show_format(
	struct device *dev, struct device_attribute *attr, char *buf
)
{
	return cc_show(dev, attr, buf, REG_FORMAT);
}

static ssize_t ct_store_format(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	return cc_store(dev, attr, buf, len, REG_FORMAT);
}

// START

static ssize_t ct_show_start(
	struct device *dev, struct device_attribute *attr, char *buf
)
{
	return cc_show(dev, attr, buf, REG_START);
}

static ssize_t ct_store_start(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	return cc_store(dev, attr, buf, len, REG_START);
}

// MODE

static ssize_t ct_show_mode(
	struct device *dev, struct device_attribute *attr, char *buf
)
{
	return cc_show(dev, attr, buf, REG_MODE);
}

static ssize_t ct_store_mode(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	return cc_store(dev, attr, buf, len, REG_MODE);
}

// VALID

static ssize_t ct_show_valid(
	struct device *dev, struct device_attribute *attr, char *buf
)
{
	return cc_show(dev, attr, buf, REG_VALID);
}

static ssize_t ct_store_valid(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	return cc_store(dev, attr, buf, len, REG_VALID);
}

// KEY (STORE)

static ssize_t ct_store_key_0(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	return cc_store(dev, attr, buf, len, REG_KEY_0);
}

static ssize_t ct_store_key_1(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	return cc_store(dev, attr, buf, len, REG_KEY_1);
}

static ssize_t ct_store_key_2(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_KEY_2);
}

static ssize_t ct_store_key_3(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_KEY_3);
}
static ssize_t ct_store_key_4(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	return cc_store(dev, attr, buf, len, REG_KEY_4);
}

static ssize_t ct_store_key_5(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	return cc_store(dev, attr, buf, len, REG_KEY_5);
}

static ssize_t ct_store_key_6(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_KEY_6);
}

static ssize_t ct_store_key_7(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_KEY_7);
}

// IV (STORE)

static ssize_t ct_store_iv_0(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_IV_0);
}

static ssize_t ct_store_iv_1(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_IV_1);
}
static ssize_t ct_store_iv_2(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_IV_2);
}

static ssize_t ct_store_iv_3(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_IV_3);
}

// IN

static ssize_t ct_show_in_0(
        struct device *dev, struct device_attribute *attr, char *buf
)
{ 
        return cc_show(dev, attr, buf, REG_IN_0);
}

static ssize_t ct_show_in_1(
        struct device *dev, struct device_attribute *attr, char *buf
)
{ 
        return cc_show(dev, attr, buf, REG_IN_1);
}
static ssize_t ct_show_in_2(
        struct device *dev, struct device_attribute *attr, char *buf
)
{ 
        return cc_show(dev, attr, buf, REG_IN_2);
}

static ssize_t ct_show_in_3(
        struct device *dev, struct device_attribute *attr, char *buf
)
{ 
        return cc_show(dev, attr, buf, REG_IN_3);
}


static ssize_t ct_store_in_0(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_IN_0);
}

static ssize_t ct_store_in_1(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_IN_1);
}
static ssize_t ct_store_in_2(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_IN_2);
}

static ssize_t ct_store_in_3(
        struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{ 
        return cc_store(dev, attr, buf, len, REG_IN_3);
}

// OUT

static ssize_t ct_show_out_0(
        struct device *dev, struct device_attribute *attr, char *buf
)
{ 
        return cc_show(dev, attr, buf, REG_OUT_0);
}

static ssize_t ct_show_out_1(
        struct device *dev, struct device_attribute *attr, char *buf
)
{ 
        return cc_show(dev, attr, buf, REG_OUT_1);
}
static ssize_t ct_show_out_2(
        struct device *dev, struct device_attribute *attr, char *buf
)
{ 
        return cc_show(dev, attr, buf, REG_OUT_2);
}

static ssize_t ct_show_out_3(
        struct device *dev, struct device_attribute *attr, char *buf
)
{ 
        return cc_show(dev, attr, buf, REG_OUT_3);
}


static ssize_t ct_show_in_char(
	struct device *dev, struct device_attribute *attr, char *buf
)
{
	struct crypto_core *ct = dev_get_drvdata(dev);
	uint64_t val_0, val_1, val_2, val_3;
	uint8_t c[16];
	val_0 = readl_relaxed(ct->base + REG_IN_0);
	val_1 = readl_relaxed(ct->base + REG_IN_1);
	val_2 = readl_relaxed(ct->base + REG_IN_2);
	val_3 = readl_relaxed(ct->base + REG_IN_3);
	uint32_to_uint8(val_0, c);
	uint32_to_uint8(val_1, c+4);
	uint32_to_uint8(val_2, c+8);
	uint32_to_uint8(val_3, c+12);
	

        return scnprintf(buf, PAGE_SIZE, 
		"%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n", 
		c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], 
		c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]
	);

}
static ssize_t ct_show_out_char(
	struct device *dev, struct device_attribute *attr, char *buf
)
{
	struct crypto_core *ct = dev_get_drvdata(dev);
	uint64_t val_0, val_1, val_2, val_3;
	uint8_t c[16];
	val_0 = readl_relaxed(ct->base + REG_OUT_0);
	val_1 = readl_relaxed(ct->base + REG_OUT_1);
	val_2 = readl_relaxed(ct->base + REG_OUT_2);
	val_3 = readl_relaxed(ct->base + REG_OUT_3);
	
        //return scnprintf(buf, PAGE_SIZE, "%llx %llx %llx %llx\n", val_0, val_1, val_2, val_3);
	uint32_to_uint8(val_0, c);
	uint32_to_uint8(val_1, c+4);
	uint32_to_uint8(val_2, c+8);
	uint32_to_uint8(val_3, c+12);
	

        return scnprintf(buf, PAGE_SIZE, 
		"%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n", 
		c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], 
		c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]
	);

}

static ssize_t ct_store_key_char(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	const char *return_buf = "101";
	uint32_t key_to_32[8];
	char temp_buf[32];
	for(uint8_t i = 0; i < 8; i += 1)
	{
		key_to_32[i] = char_to_uint32(buf+i*4);
	}
	sprintf(temp_buf, "%lu", (unsigned long)key_to_32[0]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_KEY_0);
	sprintf(temp_buf, "%lu", (unsigned long)key_to_32[1]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_KEY_1);
	sprintf(temp_buf, "%lu", (unsigned long)key_to_32[2]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_KEY_2);
	sprintf(temp_buf, "%lu", (unsigned long)key_to_32[3]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_KEY_3);
	sprintf(temp_buf, "%lu", (unsigned long)key_to_32[4]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_KEY_4);
	sprintf(temp_buf, "%lu", (unsigned long)key_to_32[5]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_KEY_5);
	sprintf(temp_buf, "%lu", (unsigned long)key_to_32[6]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_KEY_6);
	sprintf(temp_buf, "%lu", (unsigned long)key_to_32[7]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_KEY_7);

	return cc_store(dev, attr, return_buf, len, REG_KEY_CHAR);
}

static ssize_t ct_store_iv_char(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	const char *return_buf = "202";
	uint32_t iv_to_32[4];
	char temp_buf[32];
	for(uint8_t i = 0; i < 4; i += 1)
	{
		iv_to_32[i] = char_to_uint32(buf+i*4);
	}

	sprintf(temp_buf, "%lu", (unsigned long)iv_to_32[0]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_IV_0);
	sprintf(temp_buf, "%lu", (unsigned long)iv_to_32[1]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_IV_1);
	sprintf(temp_buf, "%lu", (unsigned long)iv_to_32[2]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_IV_2);
	sprintf(temp_buf, "%lu", (unsigned long)iv_to_32[3]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_IV_3);
	return cc_store(dev, attr, return_buf, len, REG_IV_CHAR);
}
static ssize_t ct_store_in_char(
	struct device *dev, struct device_attribute *attr, const char *buf, size_t len
)
{
	const char *return_buf = "202";
	uint32_t in_to_32[4];
	char temp_buf[32];
	for(uint8_t i = 0; i < 4; i += 1)
	{
		in_to_32[i] = char_to_uint32(buf+i*4);
	}

	sprintf(temp_buf, "%lu", (unsigned long)in_to_32[0]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_IN_0);
	sprintf(temp_buf, "%lu", (unsigned long)in_to_32[1]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_IN_1);
	sprintf(temp_buf, "%lu", (unsigned long)in_to_32[2]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_IN_2);
	sprintf(temp_buf, "%lu", (unsigned long)in_to_32[3]);
	cc_store(dev, attr, temp_buf, sizeof(temp_buf), REG_IN_3);
	return cc_store(dev, attr, return_buf, len, REG_IN_CHAR);
}

static DEVICE_ATTR(proc_id,	S_IRUGO, 		ct_show_id,	NULL);
static DEVICE_ATTR(start, 	S_IRUGO | S_IWUSR, 	ct_show_start, 	ct_store_start);
static DEVICE_ATTR(mode, 	S_IRUGO | S_IWUSR, 	ct_show_mode, 	ct_store_mode);
static DEVICE_ATTR(format, 	S_IRUGO | S_IWUSR, 	ct_show_format,	ct_store_format);
static DEVICE_ATTR(valid, 	S_IRUGO | S_IWUSR, 	ct_show_valid,	ct_store_valid);

static DEVICE_ATTR(key_0, 	S_IWUSR, 		NULL, 		ct_store_key_0);
static DEVICE_ATTR(key_1, 	S_IWUSR, 		NULL, 		ct_store_key_1);
static DEVICE_ATTR(key_2, 	S_IWUSR, 		NULL, 		ct_store_key_2);
static DEVICE_ATTR(key_3, 	S_IWUSR, 		NULL, 		ct_store_key_3);
static DEVICE_ATTR(key_4, 	S_IWUSR, 		NULL, 		ct_store_key_4);
static DEVICE_ATTR(key_5, 	S_IWUSR, 		NULL, 		ct_store_key_5);
static DEVICE_ATTR(key_6, 	S_IWUSR, 		NULL, 		ct_store_key_6);
static DEVICE_ATTR(key_7, 	S_IWUSR, 		NULL, 		ct_store_key_7);

static DEVICE_ATTR(key_char,	S_IWUSR,		NULL,		ct_store_key_char);

static DEVICE_ATTR(iv_0, 	S_IWUSR, 		NULL, 		ct_store_iv_0);
static DEVICE_ATTR(iv_1, 	S_IWUSR, 		NULL, 		ct_store_iv_1);
static DEVICE_ATTR(iv_2, 	S_IWUSR, 		NULL, 		ct_store_iv_2);
static DEVICE_ATTR(iv_3, 	S_IWUSR, 		NULL, 		ct_store_iv_3);

static DEVICE_ATTR(iv_char,	S_IWUSR,		NULL,		ct_store_iv_char);

static DEVICE_ATTR(in_0, 	S_IRUGO | S_IWUSR, 	ct_show_in_0,	ct_store_in_0);
static DEVICE_ATTR(in_1, 	S_IRUGO | S_IWUSR, 	ct_show_in_1,	ct_store_in_1);
static DEVICE_ATTR(in_2, 	S_IRUGO | S_IWUSR, 	ct_show_in_2,	ct_store_in_2);
static DEVICE_ATTR(in_3, 	S_IRUGO | S_IWUSR, 	ct_show_in_3,	ct_store_in_3);

static DEVICE_ATTR(in_char,	S_IRUGO | S_IWUSR,	ct_show_in_char,ct_store_in_char);

static DEVICE_ATTR(out_0, 	S_IRUGO, 		ct_show_out_0,	NULL);
static DEVICE_ATTR(out_1, 	S_IRUGO, 		ct_show_out_1,	NULL);
static DEVICE_ATTR(out_2, 	S_IRUGO, 		ct_show_out_2,	NULL);
static DEVICE_ATTR(out_3, 	S_IRUGO, 		ct_show_out_3,	NULL);

static DEVICE_ATTR(out_char,	S_IRUGO,		ct_show_out_char,NULL);
/*
*/

static struct attribute *ct_attributes[] = {
	&dev_attr_proc_id.attr,
	&dev_attr_mode.attr,
	&dev_attr_format.attr,
	&dev_attr_start.attr,
	&dev_attr_valid.attr,

	&dev_attr_key_0.attr,
	&dev_attr_key_1.attr,
	&dev_attr_key_2.attr,
	&dev_attr_key_3.attr,
	&dev_attr_key_4.attr,
	&dev_attr_key_5.attr,
	&dev_attr_key_6.attr,
	&dev_attr_key_7.attr,
	&dev_attr_key_char.attr,
	&dev_attr_iv_0.attr,
	&dev_attr_iv_1.attr,
	&dev_attr_iv_2.attr,
	&dev_attr_iv_3.attr,
	&dev_attr_iv_char.attr,

	&dev_attr_in_0.attr,
	&dev_attr_in_1.attr,
	&dev_attr_in_2.attr,
	&dev_attr_in_3.attr,
	&dev_attr_in_char.attr,

	&dev_attr_out_0.attr,
	&dev_attr_out_1.attr,
	&dev_attr_out_2.attr,
	&dev_attr_out_3.attr,
	&dev_attr_out_char.attr,
	NULL,
};

static const struct attribute_group ct_attr_group = {
	.attrs = ct_attributes,
};

static void ct_init(struct crypto_core *ct)
{

}

static int ct_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	//struct resource *res;
	struct crypto_core *ct;
	ct = devm_kzalloc(dev, sizeof(*ct), GFP_KERNEL);
	if(!ct)
	{
		return -ENOMEM;
	}
	ct->dev = dev;
	ct->base = devm_ioremap(dev, CRYPTO_CORE_ADDR, CRYPTO_CORE_SIZE);
	if(!ct->base)
	{
		return -EINVAL;
	}
	platform_set_drvdata(pdev, ct);
	ct_init(ct);
	printk(KERN_INFO "Driver loaded!\n");
	return sysfs_create_group(&dev->kobj, &ct_attr_group);
}

static int ct_remove(struct platform_device *pdev)
{
	struct crypto_core *ct = platform_get_drvdata(pdev);
	sysfs_remove_group(&ct->dev->kobj, &ct_attr_group);
	return 0;
}

static const struct of_device_id ct_of_match[] = {
	{.compatible = "crypto-core",},
	{}
};

MODULE_DEVICE_TABLE(of, ct_of_match);

static struct platform_driver ct_driver = {
	.probe = ct_probe,
	.remove = ct_remove,
	.driver = {
		.name = "crypto_core",
		.of_match_table = of_match_ptr(ct_of_match),
	},
};

module_platform_driver(ct_driver);
MODULE_DESCRIPTION("Crypto Core driver");
MODULE_AUTHOR("Alberto Castronovo");
MODULE_LICENSE("GPL");
