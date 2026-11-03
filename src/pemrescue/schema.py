"""语义层：把通用 ASN.1 树映射到 X.509 / 密钥结构，给节点命名并标出缺失字段。"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from . import der
from . import values as V
from .der import CLS_CONTEXT, CLS_UNIVERSAL, DAMAGED_AT_END, Node, Status
from .oids import NAME_ATTRS


def u(*nums: int) -> frozenset:
    return frozenset((CLS_UNIVERSAL, n) for n in nums)


def ctx(n: int) -> frozenset:
    return frozenset({(CLS_CONTEXT, n)})


INTEGER = u(der.INTEGER)
BOOL = u(der.BOOLEAN)
BITS = u(der.BIT_STRING)
OCTETS = u(der.OCTET_STRING)
OID = u(der.OID)
SEQ = u(der.SEQUENCE)
SET = u(der.SET)
TIME = u(der.UTC_TIME, der.GENERALIZED_TIME)


@dataclass(frozen=True)
class F:
    name: str
    tags: frozenset | None = None  # None 表示 ANY
    optional: bool = False
    fields: tuple[F, ...] | None = None  # SEQUENCE / SET 成员
    of: F | None = None  # SEQUENCE OF / SET OF 元素
    explicit: F | None = None  # [n] EXPLICIT 内层类型
    encap: F | None = None  # OCTET/BIT STRING 内封装的 DER
    resolve: Callable[[dict[str, Node]], F | None] | None = None  # 依赖兄弟字段动态确定类型
    render: Callable[[Node], str | None] | None = None
    summary: Callable[[Node], str | None] | None = None
    report: bool = False  # 是否在末尾输出其 hex 值
    type_label: str | None = None  # 缺失时显示的类型


def S(name, *fields, **kw) -> F:
    return F(name, SEQ, fields=tuple(fields), **kw)


# ======================================================================
# 结构描述
# ======================================================================


def name_summary(node: Node) -> str | None:
    parts = []
    for rdn in node.children:
        for atav in rdn.children:
            t = atav.child("type")
            v = atav.child("value")
            oid = V.oid_of(t)
            if oid is None:
                parts.append("?…")
                continue
            key = NAME_ATTRS.get(oid, (oid, oid))[1]
            if v is None or v.status is Status.MISSING:
                parts.append(f"{key}=…")
            elif v.cls == CLS_UNIVERSAL and v.tag in V.STRING_TAGS:
                s = V.decode_string(v)
                parts.append(f"{key}={s}" + ("" if v.status is Status.COMPLETE else "…"))
            else:
                parts.append(f"{key}=#{v.content.hex()}")
    if not parts:
        return "(空)" if node.status is Status.COMPLETE else None
    s = ", ".join(parts)
    if node.damaged:
        s += "  …（不完整）"
    return s


def atav_summary(node: Node) -> str | None:
    oid = V.oid_of(node.child("type"))
    return NAME_ATTRS[oid][0] if oid in NAME_ATTRS else None


def validity_summary(node: Node) -> str | None:
    nb, na = node.child("notBefore"), node.child("notAfter")
    if nb is None or nb.status is Status.MISSING:
        return None
    a = V.describe_time(nb)
    b = V.describe_time(na) if na is not None and na.status is not Status.MISSING else "?"
    return f"{a}  →  {b}"


def alg_oid(node: Node | None) -> str | None:
    if node is None:
        return None
    return V.oid_of(node.child("algorithm"))


def alg_summary(node: Node) -> str | None:
    oid = alg_oid(node)
    if oid is None:
        return None
    from .oids import oid_name

    return oid_name(oid) or oid


OID_RSA = "1.2.840.113549.1.1.1"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_EC = "1.2.840.10045.2.1"
OID_DSA = "1.2.840.10040.4.1"
RAW_KEY_OIDS = {
    "1.3.101.110": ("X25519", 32),
    "1.3.101.111": ("X448", 56),
    "1.3.101.112": ("Ed25519", 32),
    "1.3.101.113": ("Ed448", 57),
}
PKCS12_PBE = {f"1.2.840.113549.1.12.1.{i}" for i in range(1, 7)}
PBES1 = {"1.2.840.113549.1.5.3", "1.2.840.113549.1.5.10", "1.2.840.113549.1.5.1", "1.2.840.113549.1.5.4",
         "1.2.840.113549.1.5.6", "1.2.840.113549.1.5.11"}
CBC_IV = {"2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.42",
          "1.2.840.113549.3.7", "1.3.14.3.2.7"}
GCM = {"2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.46"}


def alg_params(sib: dict[str, Node]) -> F | None:
    oid = V.oid_of(sib.get("algorithm"))
    if oid == OID_EC:
        return F("namedCurve", None, optional=True)
    if oid == OID_DSA:
        return S("Dss-Parms", F("p", INTEGER, report=True), F("q", INTEGER, report=True), F("g", INTEGER, report=True),
                 optional=True)
    if oid == "1.2.840.113549.1.5.13":
        return S("PBES2-params", AlgId("keyDerivationFunc"), AlgId("encryptionScheme"), optional=True)
    if oid == "1.2.840.113549.1.5.12":
        return S(
            "PBKDF2-params",
            F("salt", OCTETS, report=True),
            F("iterationCount", INTEGER),
            F("keyLength", INTEGER, optional=True),
            AlgId("prf", optional=True),
            optional=True,
        )
    if oid == "1.3.6.1.4.1.11591.4.11":
        return S(
            "scrypt-params",
            F("salt", OCTETS, report=True),
            F("costParameter (N)", INTEGER),
            F("blockSize (r)", INTEGER),
            F("parallelizationParameter (p)", INTEGER),
            F("keyLength", INTEGER, optional=True),
            optional=True,
        )
    if oid in PKCS12_PBE or oid in PBES1:
        return S("PBEParameter", F("salt", OCTETS, report=True), F("iterations", INTEGER), optional=True)
    if oid in CBC_IV:
        return F("iv", OCTETS, optional=True, report=True)
    if oid in GCM:
        return S("GCMParameters", F("nonce", OCTETS, report=True), F("icvLen", INTEGER, optional=True), optional=True)
    if oid == OID_RSA_PSS:
        return S(
            "RSASSA-PSS-params",
            F("hashAlgorithm", ctx(0), True, explicit=AlgId("hashAlgorithm")),
            F("maskGenAlgorithm", ctx(1), True, explicit=AlgId("maskGenAlgorithm")),
            F("saltLength", ctx(2), True, explicit=F("saltLength", INTEGER)),
            F("trailerField", ctx(3), True, explicit=F("trailerField", INTEGER)),
            optional=True,
        )
    return None


def AlgId(name: str, optional: bool = False, report: bool = False) -> F:
    return S(
        name,
        F("algorithm", OID),
        F("parameters", None, optional=True, resolve=alg_params),
        optional=optional,
        report=report,
        summary=alg_summary,
        type_label="AlgorithmIdentifier",
    )


# ---------------------------------------------------------------- 密钥

RSAPublicKey = S(
    "RSAPublicKey",
    F("modulus (n)", INTEGER, report=True),
    F("publicExponent (e)", INTEGER, report=True),
)

RSAPrivateKey = S(
    "RSAPrivateKey",
    F("version", INTEGER),
    F("modulus (n)", INTEGER, report=True),
    F("publicExponent (e)", INTEGER, report=True),
    F("privateExponent (d)", INTEGER, report=True),
    F("prime1 (p)", INTEGER, report=True),
    F("prime2 (q)", INTEGER, report=True),
    F("exponent1 (dP)", INTEGER, report=True),
    F("exponent2 (dQ)", INTEGER, report=True),
    F("coefficient (qInv)", INTEGER, report=True),
    F("otherPrimeInfos", SEQ, optional=True),
)

DSAPrivateKeyTraditional = S(
    "DSAPrivateKey",
    F("version", INTEGER),
    F("p", INTEGER, report=True),
    F("q", INTEGER, report=True),
    F("g", INTEGER, report=True),
    F("publicKey (y)", INTEGER, report=True),
    F("privateKey (x)", INTEGER, report=True),
)

ECPrivateKey = S(
    "ECPrivateKey",
    F("version", INTEGER),
    F("privateKey", OCTETS, render=V.render_ec_scalar, report=True),
    F("parameters", ctx(0), True, explicit=F("namedCurve", None)),
    F("publicKey", ctx(1), True, explicit=F("publicKey", BITS, render=V.render_ec_point, report=True)),
)


def spk_resolve(sib: dict[str, Node]) -> F | None:
    oid = alg_oid(sib.get("algorithm"))
    if oid in (OID_RSA, OID_RSA_PSS):
        return F("subjectPublicKey", BITS, encap=RSAPublicKey, report=True)
    if oid == OID_DSA:
        return F("subjectPublicKey", BITS, encap=F("publicKey (y)", INTEGER, report=True), report=True)
    if oid == OID_EC:
        return F("subjectPublicKey", BITS, render=V.render_ec_point, report=True)
    if oid in RAW_KEY_OIDS:
        label = RAW_KEY_OIDS[oid][0]
        return F("subjectPublicKey", BITS, render=V.render_raw_key(f"{label} 原始公钥"), report=True)
    return None


def spki_summary(node: Node) -> str | None:
    from .oids import oid_name

    alg = node.child("algorithm")
    oid = alg_oid(alg)
    if oid is None:
        return None
    s = oid_name(oid) or oid
    if oid == OID_EC and alg is not None:
        curve = V.oid_of(alg.child("parameters"))
        if curve:
            s += f" {oid_name(curve) or curve}"
    spk = node.child("subjectPublicKey")
    if spk is not None and spk.encapsulated:
        mod = spk.encapsulated[0].child("modulus (n)")
        if mod is not None and mod.status is Status.COMPLETE:
            s += f"，{int.from_bytes(mod.content, 'big').bit_length()} bit"
        elif mod is not None:
            s += "（模数不完整）"
    elif spk is None or spk.status is Status.MISSING:
        s += "（公钥值缺失）"
    return s


def extensions_summary(node: Node) -> str | None:
    seq = node.children[0] if node.children else None
    if seq is None or seq.status is Status.MISSING:
        return None
    names = [ext_summary(e) or "?" for e in seq.children if e.status is not Status.MISSING]
    return f"{len(names)} 个：" + ", ".join(names) if names else None


SubjectPublicKeyInfo = S(
    "subjectPublicKeyInfo",
    AlgId("algorithm"),
    F("subjectPublicKey", BITS, resolve=spk_resolve, report=True),
    type_label="SubjectPublicKeyInfo",
    summary=spki_summary,
)


def pk8_resolve(sib: dict[str, Node]) -> F | None:
    oid = alg_oid(sib.get("privateKeyAlgorithm"))
    if oid in (OID_RSA, OID_RSA_PSS):
        return F("privateKey", OCTETS, encap=RSAPrivateKey)
    if oid == OID_EC:
        return F("privateKey", OCTETS, encap=ECPrivateKey)
    if oid == OID_DSA:
        return F("privateKey", OCTETS, encap=F("privateKey (x)", INTEGER, report=True))
    if oid in RAW_KEY_OIDS:
        label = RAW_KEY_OIDS[oid][0]
        return F(
            "privateKey",
            OCTETS,
            encap=F("CurvePrivateKey", OCTETS, render=V.render_raw_key(f"{label} 原始私钥"), report=True),
        )
    return None


PrivateKeyInfo = S(
    "PrivateKeyInfo",
    F("version", INTEGER),
    AlgId("privateKeyAlgorithm"),
    F("privateKey", OCTETS, resolve=pk8_resolve),
    F("attributes", ctx(0), optional=True),
    F("publicKey", ctx(1), optional=True, render=V.render_raw_key("公钥"), report=True),
)

EncryptedPrivateKeyInfo = S(
    "EncryptedPrivateKeyInfo",
    AlgId("encryptionAlgorithm"),
    F("encryptedData", OCTETS, report=True),
)

# ---------------------------------------------------------------- 证书

AttributeTypeAndValue = S("attribute", F("type", OID), F("value", None), summary=atav_summary)
RDN = F("RDN", SET, of=AttributeTypeAndValue)


def Name(name: str) -> F:
    return F(name, SEQ, of=RDN, summary=name_summary, report=True, type_label="Name")


GeneralNames = F("GeneralNames", SEQ, of=F("generalName", None, render=V.render_general_name))

EXT_SPECS: dict[str, F] = {
    "2.5.29.19": S(
        "BasicConstraints",
        F("cA", BOOL, optional=True),
        F("pathLenConstraint", INTEGER, optional=True),
    ),
    "2.5.29.15": F("KeyUsage", BITS, render=V.render_key_usage),
    "2.5.29.37": F("ExtKeyUsageSyntax", SEQ, of=F("keyPurposeId", OID)),
    "2.5.29.17": GeneralNames,
    "2.5.29.18": GeneralNames,
    "2.5.29.14": F("SubjectKeyIdentifier", OCTETS),
    "2.5.29.35": S(
        "AuthorityKeyIdentifier",
        F("keyIdentifier", ctx(0), optional=True),
        F("authorityCertIssuer", ctx(1), optional=True),
        F("authorityCertSerialNumber", ctx(2), optional=True),
    ),
    "1.3.6.1.5.5.7.1.1": F(
        "AuthorityInfoAccessSyntax",
        SEQ,
        of=S("AccessDescription", F("accessMethod", OID),
             F("accessLocation", None, render=V.render_general_name)),
    ),
}


def ext_resolve(sib: dict[str, Node]) -> F | None:
    spec = EXT_SPECS.get(V.oid_of(sib.get("extnID")) or "")
    if spec is None:
        return None
    return F("extnValue", OCTETS, encap=spec)


def ext_summary(node: Node) -> str | None:
    oid = V.oid_of(node.child("extnID"))
    if oid is None:
        return None
    from .oids import oid_name

    crit = node.child("critical")
    c = "  [critical]" if crit is not None and crit.content[:1] not in (b"", b"\x00") else ""
    return (oid_name(oid) or oid) + c


Extension = S(
    "extension",
    F("extnID", OID),
    F("critical", BOOL, optional=True),
    F("extnValue", OCTETS, resolve=ext_resolve),
    summary=ext_summary,
)

TBSCertificate = S(
    "tbsCertificate",
    F("version", ctx(0), True, explicit=F("version", INTEGER, render=V.render_version)),
    F("serialNumber", INTEGER, report=True),
    AlgId("signature"),
    Name("issuer"),
    S("validity", F("notBefore", TIME), F("notAfter", TIME), summary=validity_summary,
      type_label="Validity"),
    Name("subject"),
    replace(SubjectPublicKeyInfo, report=True),
    F("issuerUniqueID", ctx(1), optional=True),
    F("subjectUniqueID", ctx(2), optional=True),
    F("extensions", ctx(3), True, explicit=F("extensions", SEQ, of=Extension, report=True),
      summary=extensions_summary),
    type_label="TBSCertificate",
)

Certificate = S(
    "certificate",
    TBSCertificate,
    AlgId("signatureAlgorithm"),
    F("signatureValue", BITS, report=True),
)

ECParameters = F("ECParameters", None)


# ======================================================================
# 应用
# ======================================================================


def tag_matches(node: Node, spec: F) -> bool:
    if spec.tags is None:
        return True
    if node.tag is None or node.cls is None:
        return node.status is Status.HEADER_TRUNCATED
    return (node.cls, node.tag) in spec.tags


def make_missing(spec: F, truncated: bool) -> Node:
    n = Node(offset=-1, status=Status.MISSING, name=spec.name, spec=spec)
    n.optional_missing = spec.optional
    if truncated:
        n.notes.append("可选字段，无法确定是否存在" if spec.optional else "因截断丢失")
    else:
        n.notes.append("结构中缺少该必需字段")
    return n


def apply(node: Node, spec: F, sib: dict[str, Node] | None = None) -> None:
    if spec.resolve is not None:
        r = spec.resolve(sib or {})
        if r is not None and r.name != spec.name:
            node.alias = r.name
        spec = replace(r, name=spec.name, optional=spec.optional) if r else replace(spec, resolve=None)
    node.name = spec.name
    node.spec = spec
    if node.status is Status.HEADER_TRUNCATED and node.tag is None:
        node.guessed = True
    if spec.render is not None:
        node.display = spec.render

    if spec.explicit is not None and node.constructed:
        if node.children:
            apply(node.children[0], spec.explicit, sib)
            for extra in node.children[1:]:
                extra.notes.append("多余元素")
                generic(extra)
        elif node.status in DAMAGED_AT_END:
            node.children.append(make_missing(spec.explicit, True))
    elif spec.fields is not None and node.constructed:
        _match_fields(node, spec.fields)
    elif spec.of is not None and node.constructed:
        for i, ch in enumerate(node.children):
            if ch.status is Status.MALFORMED:
                continue
            apply(ch, spec.of)
            ch.name = f"{spec.of.name} #{i + 1}"
    elif spec.encap is not None and not node.constructed and node.status is not Status.HEADER_TRUNCATED:
        _encapsulate(node, spec.encap)
    else:
        generic(node, top=False)


def _match_fields(node: Node, fields: tuple[F, ...]) -> None:
    kids = list(node.children)
    named: dict[str, Node] = {}
    i = 0
    cut = node.status in DAMAGED_AT_END
    for f in fields:
        if i < len(kids):
            k = kids[i]
            if k.status is Status.MALFORMED:
                i += 1
                if i >= len(kids):
                    node.children.append(make_missing(f, True))
                    continue
                k = kids[i]
            if tag_matches(k, f):
                apply(k, f, named)
                named[f.name] = k
                i += 1
                continue
            if f.optional:
                continue
            apply(k, f, named)
            k.notes.append("标签不符")
            named[f.name] = k
            i += 1
        else:
            if cut or not f.optional:
                node.children.append(make_missing(f, cut))
    for extra in kids[i:]:
        if extra.status is not Status.MALFORMED:
            extra.notes.append("多余元素")
            generic(extra)


def _encapsulate(node: Node, spec: F) -> None:
    data = node.content
    start = node.content_offset
    if node.is_universal(der.BIT_STRING):
        if not data:
            if node.status in DAMAGED_AT_END:
                node.encapsulated = [make_missing(spec, True)]
            return
        data = data[1:]
        start += 1
    eof = node.status in DAMAGED_AT_END
    inner = der.parse(data, start, eof=eof)
    node.encapsulated = inner
    if inner:
        apply(inner[0], spec)
        for extra in inner[1:]:
            extra.notes.append("多余数据")
            generic(extra)
    elif eof:
        node.encapsulated = [make_missing(spec, True)]


def generic(node: Node, top: bool = True) -> None:
    """无结构定义时：递归识别 OCTET/BIT STRING 中封装的完整 DER。"""
    if node.constructed:
        for c in node.children:
            generic(c)
        return
    if node.status is not Status.COMPLETE or node.encapsulated is not None:
        return
    if node.is_universal(der.OCTET_STRING):
        inner = der.try_parse_exact(node.content, node.content_offset)
    elif node.is_universal(der.BIT_STRING) and node.content[:1] == b"\x00":
        inner = der.try_parse_exact(node.content[1:], node.content_offset + 1)
    else:
        return
    if inner:
        node.encapsulated = inner
        for c in inner:
            generic(c)
