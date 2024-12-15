import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# Nama Program
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

    # Convert public key to PEM format using serialization
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Save to file
    with open("output_data.txt", "w") as f:
        f.write("Data yang di-hash (SHA3-512):\n")
        f.write(hashed_data.hex() + "\n\n")
        f.write("Tanda tangan digital (ECDSA):\n")
        f.write(signature.hex() + "\n\n")
        f.write("Kunci Publik:\n")
        f.write(public_key_pem)

    return hashed_data, private_key


def verify_data(hashed_data, private_key):
    try:
        input_hash = bytes.fromhex(input("Masukkan Hash (SHA3-512): "))
        input_signature = bytes.fromhex(input("Masukkan Tanda Tangan Digital: "))
        public_key = private_key.public_key()
        public_key.verify(input_signature, input_hash, ec.ECDSA(hashes.SHA3_512()))
        print("\nData valid! Hash dan tanda tangan cocok.\n")
    except (ValueError, InvalidSignature):
        print(
            "\nLog error: Kunci yang Anda berikan salah atau hash/private key tidak cocok.\n"
        )


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
                    hashed_data, private_key = generate_signature(data)
                    print("\nData terenkripsi dan disimpan di file output_data.txt\n")
                    break
                else:
                    print("Pilihan tidak valid.")

        elif pilihan == "2":
            print("\nVerifikasi Data:")
            if "hashed_data" in locals() and "private_key" in locals():
                verify_data(hashed_data, private_key)
            else:
                print("\nData belum terenkripsi. Silakan input data terlebih dahulu.\n")

        elif pilihan == "3":
            print("Program dibatalkan.")
            break
        else:
            print("Pilihan tidak valid. Silakan coba lagi.")
