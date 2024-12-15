from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


def nama_program():
    print("\n====================================")
    print("PROGRAM: VERIFIKASI DATA PRIBADI")
    print("====================================\n")


def read_files():
    try:
        # Baca file public key
        with open("public_key.pem", "r") as pub_file:
            public_key_pem = pub_file.read().strip()  # Hilangkan newline atau spasi ekstra

        # Baca file hash dan tanda tangan digital
        with open("hashed_data_and_private_key.txt", "r") as hash_file:
            lines = hash_file.readlines()
            received_hash = lines[1].strip()  # Baris kedua adalah hash
            signature = lines[3].strip()      # Baris keempat adalah tanda tangan digital

        # Pastikan format hash dan signature adalah heksadesimal
        if not all(c in "0123456789abcdefABCDEF" for c in received_hash):
            raise ValueError("Hash bukan format heksadesimal!")
        if not all(c in "0123456789abcdefABCDEF" for c in signature):
            raise ValueError("Tanda tangan bukan format heksadesimal!")

        return public_key_pem, received_hash, signature
    except FileNotFoundError as e:
        print(f"File tidak ditemukan: {e}")
        return None, None, None
    except ValueError as e:
        print(f"Kesalahan format: {e}")
        return None, None, None



def verify_signature(data, received_hash, signature, public_key_pem):
    try:
        # Convert public key from PEM format
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

        # Recalculate hash of the received data
        data_str = f"{data['nama']}|{data['nik']}|{data['tanggal_lahir']}|{data['alamat']}|{data['gender']}"
        data_bytes = data_str.encode("utf-8")

        digest = hashes.Hash(hashes.SHA3_512())
        digest.update(data_bytes)
        calculated_hash = digest.finalize()

        # Compare recalculated hash with received hash
        if calculated_hash.hex() != received_hash:
            print("Hash tidak cocok! Data mungkin telah dimodifikasi.")
            return False

        # Verify the digital signature using the public key
        public_key.verify(
            bytes.fromhex(signature),
            bytes.fromhex(received_hash),
            ec.ECDSA(hashes.SHA3_512()),
        )
        print("Data valid! Tanda tangan dan hash cocok.")
        return True
    except InvalidSignature:
        print("Tanda tangan tidak valid! Data mungkin telah dimodifikasi.")
        return False
    except Exception as e:
        print(f"Terjadi kesalahan selama verifikasi: {e}")
        return False


def main():
    nama_program()

    # Input data dari penerima
    print("Masukkan data yang diterima:")
    data = {
        "nama": input("Nama: "),
        "nik": input("NIK: "),
        "tanggal_lahir": input("Tanggal Lahir (DD-MM-YYYY): "),
        "alamat": input("Alamat: "),
        "gender": input("Gender: "),
    }

    # Baca file hash, signature, dan public key
    public_key_pem, received_hash, signature = read_files()

    if public_key_pem and received_hash and signature:
        print("\nMemverifikasi data...")
        valid = verify_signature(data, received_hash, signature, public_key_pem)

        if valid:
            print("\nProses verifikasi berhasil. Data asli dan tidak dimodifikasi.")
        else:
            print("\nProses verifikasi gagal. Data tidak valid.")
    else:
        print("\nGagal membaca file yang diperlukan untuk verifikasi.")


if __name__ == "__main__":
    main()
