from app.modules.ioc.detect import IocType, classify, defang, extract, refang


def test_refang():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("1.2.3(.)4") == "1.2.3.4"
    assert refang("bad[dot]org") == "bad.org"


def test_defang_roundtrip():
    assert defang("https://evil.com") == "hxxps://evil[.]com"
    assert refang(defang("http://a.b.c/x")) == "http://a.b.c/x"


def test_classify_types():
    assert classify("8.8.8.8").type == IocType.IPV4
    assert classify("2606:4700:4700::1111").type == IocType.IPV6
    assert classify("example.com").type == IocType.DOMAIN
    assert classify("https://example.com/x").type == IocType.URL
    assert classify("44d88612fea8a8f36de82e1278abb02f").type == IocType.MD5
    assert classify("3395856ce81f2b7382dee72602f798b642f14140").type == IocType.SHA1
    assert classify("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f").type == IocType.SHA256
    assert classify("not an ioc") is None


def test_internal_flags():
    assert classify("10.0.0.5").internal
    assert classify("192.168.1.1").internal
    assert classify("127.0.0.1").internal
    assert classify("fileserver.corp").internal
    assert not classify("185.220.101.1").internal


def test_file_names_are_not_domains():
    assert classify("invoice.pdf") is None
    assert classify("payload.ps1") is None


def test_extract_from_log():
    text = (
        "Oct 17 03:12:44 fw01 deny src=10.10.5.20 dst=185.220.101.1 dport=443\n"
        "User clicked hxxps://login-micros0ft[.]com/verify?id=1, attachment invoice.pdf "
        "sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f from bob@corp-mail.com"
    )
    found = {(i.value, i.type) for i in extract(text)}
    assert ("10.10.5.20", IocType.IPV4) in found
    assert ("185.220.101.1", IocType.IPV4) in found
    assert ("https://login-micros0ft.com/verify?id=1", IocType.URL) in found
    assert any(t == IocType.SHA256 for _, t in found)
    # domen iz URL-a i iz mejla se ne duplira, fajl nije domen
    assert not any(t == IocType.DOMAIN for _, t in found)


def test_extract_dedup_and_times_ignored():
    found = extract("8.8.8.8 8.8.8.8 at 12:30:45")
    assert [i.value for i in found] == ["8.8.8.8"]
