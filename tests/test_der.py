from pemrescue import der
from pemrescue.der import Status


def test_complete_sequence():
    data = bytes.fromhex("3006020101020102")
    (n,) = der.parse(data)
    assert n.status is Status.COMPLETE and len(n.children) == 2
    assert [c.content for c in n.children] == [b"\x01", b"\x02"]
    assert not n.damaged


def test_truncated_content():
    data = bytes.fromhex("3006020101020102")[:-1]
    (n,) = der.parse(data)
    assert n.status is Status.TRUNCATED
    assert n.children[0].status is Status.COMPLETE
    last = n.children[1]
    assert last.status is Status.TRUNCATED and last.length == 1 and last.content == b""
    assert n.missing_bytes == 1


def test_header_truncated_long_length():
    data = bytes.fromhex("3082")  # 长度字段需要 2 字节，但一个都没有
    (n,) = der.parse(data)
    assert n.status is Status.HEADER_TRUNCATED and n.tag == 16


def test_header_truncated_tag_only():
    (n,) = der.parse(b"\x30")
    assert n.status is Status.HEADER_TRUNCATED and n.length is None


def test_overflow_inside_complete_parent():
    data = bytes.fromhex("3003020501")  # 子元素声称 5 字节，父结构只有 3
    (n,) = der.parse(data)
    assert n.status is Status.COMPLETE
    assert n.children[0].status is Status.OVERFLOW


def test_indefinite_length():
    data = bytes.fromhex("30800201010000")
    (n,) = der.parse(data)
    assert n.indefinite and n.status is Status.COMPLETE and len(n.children) == 1
    (t,) = der.parse(data[:-1])
    assert t.status is Status.TRUNCATED


def test_high_tag_number():
    (n,) = der.parse(bytes.fromhex("9f81000101"))
    assert n.cls == der.CLS_CONTEXT and n.tag == 128 and n.content == b"\x01"


def test_offsets_absolute_with_base():
    (n,) = der.parse(bytes.fromhex("020105"), base=100)
    assert n.offset == 100 and n.content_offset == 102


def test_every_prefix_never_raises(der_samples):
    data = der_samples["cert"]
    for i in range(len(data) + 1):
        der.parse(data[:i])
