from aegis.modules.drop_vault import crypto


def test_token_roundtrip():
    secret = b"x" * 32
    tok = crypto.make_token(secret, "file-1", ttl_seconds=60)
    assert crypto.verify_token(secret, tok, "file-1") is True


def test_token_wrong_file():
    secret = b"x" * 32
    tok = crypto.make_token(secret, "file-1", ttl_seconds=60)
    assert crypto.verify_token(secret, tok, "file-2") is False


def test_token_expired():
    secret = b"x" * 32
    tok = crypto.make_token(secret, "file-1", ttl_seconds=-1)
    assert crypto.verify_token(secret, tok, "file-1") is False