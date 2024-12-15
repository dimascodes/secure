import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def nama_program():
    print("\n====================================")
    print("PROGRAM: KELOMPOK 1")
    print("Mengamankan Data Pribadi dengan SHA3 dan Kunci Privat ECDSA")
    print("====================================\n")

def menu_program():
    print("Menu:")
    print("1. Input Data Pribadi")
    print("2. Verifikasi Data")
    print("3. Batal")

def input_data():
    data = {}
    data["nama"] = input("Masukkan Nama: ")
    data["nik"] = input("Masukkan NIK: ")
    data["tanggal_lahir"] = input("Masukkan Tanggal Lahir (DD-MM-YYYY): ")
    data["alamat"] = input("Masukkan Alamat: ")
    data["gender"] = input("Masukkan Gender: ")
    return data

def crud_menu():
    print("\nData telah diinput:")
    print("1. Lihat Data")
    print("2. Ubah Data")
    print("3. Hapus Data")
    print("4. Lanjutkan ke Enkripsi")

def generate_signature(data):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    data_str = f"{data['nama']}|{data['nik']}|{data['tanggal_lahir']}|{data['alamat']}|{data['gender']}"
    data_bytes = data_str.encode("utf-8")

    # Hash data with SHA3-512
    digest = hashes.Hash(hashes.SHA3_512())
    digest.update(data_bytes)
    hashed_data = digest.finalize()

    # Generate digital signature
    signature = private_key.sign(hashed_data, ec.ECDSA(hashes.SHA3_512()))

    # Save public key to PEM file
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open("public_key.pem", "wb") as f:
        f.write(public_key_pem)

    # Save hashed data to text file
    with open("hashed_data.txt", "w") as f:
        f.write(hashed_data.hex())

    # Save signature to text file
    with open("signature.txt", "w") as f:
        f.write(signature.hex())

    print("\nData berhasil dienkripsi dan disimpan ke file:\n")
    print("- public_key.pem (Kunci Publik)")
    print("- hashed_data.txt (Hash Data)")
    print("- signature.txt (Tanda Tangan Digital)")

    return hashed_data, signature, public_key_pem

def verify_data():
    try:
        # Load public key from PEM file
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # Load hashed data and signature from files
        with open("hashed_data.txt", "r") as f:
            hashed_data = bytes.fromhex(f.read().strip())

        with open("signature.txt", "r") as f:
            signature = bytes.fromhex(f.read().strip())

        # Verify signature
        public_key.verify(signature, hashed_data, ec.ECDSA(hashes.SHA3_512()))
        print("\nData valid! Hash dan tanda tangan cocok.\n")
    except FileNotFoundError:
        print("\nError: File tidak ditemukan. Pastikan semua file tersedia di direktori.\n")
    except (ValueError, InvalidSignature):
        print("\nError: Data tidak valid. Hash atau tanda tangan tidak cocok.\n")

# Program Utama
if __name__ == "__main__":
    while True:
        nama_program()
        menu_program()
        pilihan = input("Pilih menu (1/2/3): ")

        if pilihan == "1":
            data = input_data()

            while True:
                crud_menu()
                crud_pilihan = input("Pilih opsi CRUD (1/2/3/4): ")

                if crud_pilihan == "1":
                    print("\nData Anda:")
                    for key, value in data.items():
                        print(f"{key.capitalize()}: {value}")
                elif crud_pilihan == "2":
                    print("\nPerbarui Data Pribadi:")
                    data = input_data()
                elif crud_pilihan == "3":
                    print("\nData dihapus.")
                    data = {}
                elif crud_pilihan == "4":
                    generate_signature(data)
                    break
                else:
                    print("Pilihan tidak valid.")

        elif pilihan == "2":
            print("\nVerifikasi Data:")
            verify_data()

        elif pilihan == "3":
            print("Program dibatalkan.")
            break
        else:
            print("Pilihan tidak valid. Silakan coba lagi.")
