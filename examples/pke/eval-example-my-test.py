# Initial Settings
from openfhe import *

# import openfhe.PKESchemeFeature as Feature


def main():
    # Sample Program: Step 1: Set CryptoContext
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)

    crypto_context = GenCryptoContext(parameters)
    # Enable features that you wish to use
    crypto_context.Enable(PKESchemeFeature.PKE)
    crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
    crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)

    # Sample Program: Step 2: Key Generation

    # Generate a public/private key pair
    key_pair = crypto_context.KeyGen()

    # Generate the relinearization key
    crypto_context.EvalMultKeyGen(key_pair.secretKey)

    # Generate the rotation evaluation keys
    crypto_context.EvalRotateKeyGen(key_pair.secretKey, [1, 2, -1, -2])

    # Sample Program: Step 3: Encryption

    # First plaintext vector is encoded
    vector_of_ints1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext1 = crypto_context.MakePackedPlaintext(vector_of_ints1)

    # Second plaintext vector is encoded
    vector_of_ints2 = [3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    plaintext2 = crypto_context.MakePackedPlaintext(vector_of_ints2)

    # The encoded vectors are encrypted
    ciphertext1 = crypto_context.Encrypt(key_pair.publicKey, plaintext1)
    ciphertext2 = crypto_context.Encrypt(key_pair.publicKey, plaintext2)

    #  Sample Program: Step 4: Evaluation

    # Homomorphic additions
    ciphertext_add_result = crypto_context.EvalExample(ciphertext1, ciphertext2)


    # Sample Program: Step 5: Decryption

    # Decrypt the result of additions
    plaintext_add_result = crypto_context.Decrypt(
        ciphertext_add_result, key_pair.secretKey
    )

    print("Plaintext #1: " + str(plaintext1))
    print("Plaintext #2: " + str(plaintext2))

    # Output Results
    print("\nResults of homomorphic computations")
    print("#1 + #2 = " + str(plaintext_add_result))


if __name__ == "__main__":
    main()
