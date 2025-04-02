from Cryptodome.Hash import SHA256


def hash_MAC(path):
    file = open(path, "rb")
    data = file.read()
    file.close()
    blocks = [data[i * 1024:(i + 1) * 1024]
              for i in range(len(data) // 1024 + 1)]
    sha256 = SHA256.new()
    h = b""
    for block in reversed(blocks):
        h = SHA256.new(block + h).digest()
    return h.hex()


h2 = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8"
assert hash_MAC("6.2.birthday.mp4_download") == h2

print(hash_MAC("6.1.intro.mp4_download"))
