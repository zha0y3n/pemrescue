# pemrescue

从**被截断**的 PEM / DER 文件中尽可能提取 X.509 证书和密钥信息，并以带语义字段名的 ASN.1 树显示，标出每个字段是「完整 / 截断 / 缺失」。

- 支持：X.509 证书；RSA、EC (ECDSA)、Ed25519 / X25519 / Ed448 / X448、DSA 的公钥与私钥（PKCS#1、SEC1、PKCS#8、SubjectPublicKeyInfo、OpenSSL 传统 DSA 格式）
- 加密私钥：PKCS#8 `ENCRYPTED PRIVATE KEY` 显示加密结构（PBES2 / PBKDF2 / scrypt / PKCS#12 PBE 的算法、盐、迭代次数、IV）；传统 PEM 加密（`Proc-Type: 4,ENCRYPTED`）显示 DEK-Info 和密文。**不做解密。**
- 一个文件可以包含多个对象（证书链、证书 + 私钥、拼接的 DER），按内容自动识别 PEM / DER / 裸 Base64，不依赖扩展名
- 自带容错 DER 解析器，唯一的运行时依赖是 `rich`

## 安装

需要 Python 3.12+ 和 [uv](https://docs.astral.sh/uv/)。

```bash
cd /tmp/pemrescue
uv tool install .          # 安装后直接得到 pemrescue 命令
# 或者不安装，直接运行：
uv run pemrescue FILE
```

卸载：`uv tool uninstall pemrescue`

## 用法

```bash
pemrescue cert.pem                    # 自动识别
pemrescue key.der chain.pem           # 一次分析多个文件
cat broken.pem | pemrescue -          # 从标准输入读取
pemrescue -t rsa-private blob.bin     # 强制按某种结构解析
pemrescue --generic weird.der         # 只显示通用 ASN.1 树，不做语义标注
pemrescue --no-hex --no-summary x.pem # 精简输出
```

| 选项 | 说明 |
| --- | --- |
| `-t, --type` | 强制结构：`cert` `rsa-private` `rsa-public` `ec-private` `dsa-private` `pkcs8` `pkcs8-encrypted` `spki` `ec-params` |
| `--generic` | 不做语义解析 |
| `--max-hex N` | 树中超过 N 字节的值折叠显示（默认 96） |
| `--no-hex` | 不显示十六进制 |
| `--no-summary` | 不输出末尾的「字段值」列表 |
| `--no-color` | 禁用颜色；输出被重定向到文件或管道时自动禁用 |

**退出码**：`0` 全部完整；`1` 发现截断或损坏；`2` 无法读取文件。

## 输出说明

每个对象先输出一个信息框：名称（文件名）、类型、可用字节占声明总长度的比例、字段统计，以及编码层的问题（缺少 END 行、Base64 末尾分组不完整等）。

然后是 ASN.1 树，每行格式为：

```
偏移 类型 字段名  hl=头部长度 l=声明长度  [⚠ 状态]  = 解码后的值
```

- 偏移是解码后 DER 数据中的字节偏移，十六进制内容按同样的偏移标注
- OID 显示为名称，时间显示为 `YYYY-MM-DD hh:mm:ss UTC`，Name 汇总为 `C=CN, O=..., CN=...`
- OCTET STRING / BIT STRING 中封装的结构（公钥、私钥、扩展值）在 `↳ 封装内容` 下展开
- `⚠ 截断 23/257`：字段只拿到 23/257 字节，十六进制末尾有 `▲ 缺 N 字节`
- `✗ 字段名  缺失`：按结构应在此处但数据已经没有了
- `✗ 字段名  可选，未知`：截断点之后的 OPTIONAL 字段，无法判断原文件是否有

最后是「字段值」列表：把**完整或部分缺失**的关键字段以连续十六进制输出，每个值独占一行（不受终端宽度折行影响），可以直接复制：

- 原始类型输出值本身：INTEGER 去掉 DER 补位的前导 `00`，BIT STRING 去掉未使用位字节
- 构造类型（issuer / subject / subjectPublicKeyInfo / extensions）输出完整 DER 编码（含标签和长度），标 `DER`
- 部分缺失的字段输出已有的前缀，标 `⚠ 已有/应有 字节`
- 完全缺失的字段在末尾列一行名称

列出的字段：证书的 serialNumber、issuer、subject、subjectPublicKeyInfo、公钥分量、extensions、signatureValue；私钥的全部分量（RSA n/e/d/p/q/dP/dQ/qInv，DSA p/q/g/y/x，EC 私钥标量和公钥点，Ed25519/X25519 原始密钥）；加密私钥的 salt、IV/nonce、encryptedData；传统 PEM 加密的密文。私钥分量会**完整显示**，不做遮蔽，请注意终端输出的保管。

示例（截断到 75% 的证书，节选）：

```
╭──────────────────────────────────────────────────────────────╮
│ 名称：rsa_cert__cut75.pem                                    │
│ 类型：X.509 证书                                             │
│ 数据：705 / 939 字节（75.1%）                                │
│ ⚠ 缺少 END 行（文件可能被截断）                              │
╰──────────────────────────────────────────────────────────────╯
     0 SEQUENCE certificate  hl=4 l=935  ⚠ 截断 701/935
├──      4 SEQUENCE tbsCertificate  hl=4 l=655
│   ├──     38 SEQUENCE issuer  hl=2 l=74  = C=CN, O=PemRescue 测试组织, CN=pemrescue.example
│   ...
├──    663 SEQUENCE signatureAlgorithm  hl=2 l=13  = sha256WithRSAEncryption
└──    678 BIT STRING signatureValue  hl=4 l=257  ⚠ 截断 23/257
       682: 00 79 78 be 6a 1b c7 64 a6 fe 80 e9 a2 9f ff 30
       698: 1e 96 ea c6 09 bd e7
          ▲ 缺 234 字节

字段值

serialNumber  8 字节
123456789abcdef0

issuer  76 字节  DER
304a310b300906035504061302434e311f301d...
...
signatureValue  ⚠ 22/256 字节
7978be6a1bc764a6fe80e9a29fff301e96eac609bde7
```

## 能处理的截断情形

| 层 | 情形 | 处理方式 |
| --- | --- | --- |
| PEM | 缺 END 行 / END 行只剩一半 / 下一个 BEGIN 紧跟其后 | 读到文件末尾或下一个 BEGIN 为止，并提示 |
| PEM | BEGIN 行不完整 | 按标签前缀匹配类型 |
| Base64 | 末尾分组只有 2–3 个字符 | 解出能确定的 1–2 个字节 |
| Base64 | 末尾只剩 1 个字符 | 丢弃（只有 6 bit） |
| DER | 长度字段大于剩余数据 | 内容取到末尾，标为截断，继续解析其中的子元素 |
| DER | 标签或长度字节本身被截断 | 标为「头部截断」，在语义层按位置推测字段 |
| 语义 | 截断点之后的字段 | 按结构定义列出为缺失 |

另外也能容忍：长度超出父结构（标为「长度越界」）、BER 不定长编码、无法解析的残余字节。

## 开发

```bash
uv sync                                      # 安装开发依赖（pytest、cryptography）
uv run pytest                                # 运行测试
uv run scripts/make_samples.py samples       # 生成样本
```

`make_samples.py` 会在 `samples/intact/` 下生成 22 个完整的证书 / 密钥（含证书链、证书 + 私钥、加密私钥，口令 `pemrescue`），并在 `samples/truncated/` 下生成 132 个截断版本：PEM 去掉 END 行、END 行截一半、在 Base64 正文 25/50/75/95% 处截断（故意落在分组中间）；DER 在 10/25/50/75/95% 处截断以及只少最后 1 字节。

### 代码结构

```
src/pemrescue/
  der.py      容错 DER/BER 解析器，产出带状态的节点树
  pem.py      PEM/DER/Base64 识别与容错解码
  schema.py   证书、各类密钥的结构定义，以及把结构套到节点树上的匹配器
  values.py   INTEGER/OID/时间/字符串等的可读化（支持部分数据）
  oids.py     OID 名称表
  analyze.py  类型识别（PEM 标签 / 结构特征）与完整度统计
  render.py   rich 树形渲染
  cli.py      命令行入口
```

要支持新的结构，在 `schema.py` 里用 `F` / `S` 描述它，再在 `analyze.py` 的 `TYPES`、`PEM_LABELS` 中注册即可。
