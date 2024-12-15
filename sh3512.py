import os

from OpenSSL import crypto


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
    # Generate key pair (private and public) with elliptic curve
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_EC, 713)  # 713 adalah NID untuk kurva SECP256R1

    # Extract private and public keys
    private_key = key
    public_key = key.public_key()

    # Serialize keys to PEM format
    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
    public_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)

    # Prepare the data string and hash it using SHA3-512
    data_str = f"{data['nama']}|{data['nik']}|{data['tanggal_lahir']}|{data['alamat']}|{data['gender']}"
    data_bytes = data_str.encode("utf-8")

    # Hash the data using SHA3-512
    digest = crypto.MessageDigest("sha3_512")
    digest.update(data_bytes)
    hashed_data = digest.finalize()

    # Sign the hashed data using the private key (ECDSA)
    signature = crypto.sign(private_key, hashed_data, "sha3-512")

    # Save the public key to a .pem file
    with open("public_key.pem", "wb") as pem_file:
        pem_file.write(public_key_pem)

    # Save the private key and hash data to a text file
    with open("key_and_hash.txt", "w") as txt_file:
        txt_file.write("Hash Data (SHA3-512):\n")
        txt_file.write(hashed_data.hex() + "\n\n")
        txt_file.write("Private Key:\n")
        txt_file.write(private_key_pem.decode("utf-8"))

    print("Public key telah disimpan ke 'public_key.pem'.")
    print("Hash dan private key telah disimpan ke 'key_and_hash.txt'.")

    return hashed_data, private_key


def verify_data(hashed_data, private_key):
    try:
        input_hash = bytes.fromhex(input("Masukkan Hash (SHA3-512): "))
        input_signature = bytes.fromhex(input("Masukkan Tanda Tangan Digital: "))

        # Extract public key from the private key
        public_key = private_key.public_key()

        # Verify the signature using public key
        crypto.verify(public_key, input_signature, input_hash, "sha3-512")
        print("\nData valid! Hash dan tanda tangan cocok.\n")
    except crypto.Error:
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
                    print("\nData terenkripsi dan file telah dibuat.\n")
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
