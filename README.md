# phpass-go
便携式 PHP 密码哈希框架 Go实现

phpass 支持的首选（最安全）散列方法是 OpenBSD 风格的基于 Blowfish 的bcrypt ，我们的公共域crypt_blowfish包（用于 C 应用程序）也支持它 ，在 PHP 中称为 CRYPT_BLOWFISH，回退到基于 MD5 的加盐以及在 phpass 本身中实现的可变迭代计数密码哈希（也称为可移植哈希）。 （phpass 版本高达 0.4 还包括一个中间回退到 BSDI 样式扩展的基于 DES 的散列，在 PHP 中称为 CRYPT_EXT_DES，但是除了针对这种类型的预先存在的散列进行身份验证之外，这已被删除。）
