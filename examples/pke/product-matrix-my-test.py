# Initial Settings
from openfhe import *

def main():
        
    # Step 1: Set CryptoContext
    
    parameters = CCParamsBFVRNS()
    parameters.SetPlaintextModulus(65537)
    parameters.SetMultiplicativeDepth(2)
    
    crypto_context = GenCryptoContext(parameters)

    crypto_context.Enable(PKESchemeFeature.PKE)
    crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
    crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)
    
    # Step 2: Key generation
    
    # Generate a public/private key pair
    key_pair = crypto_context.KeyGen()

    # Generate the relinearization key
    crypto_context.EvalMultKeyGen(key_pair.secretKey)

    # Generate the rotation evaluation keys
    crypto_context.EvalRotateKeyGen(key_pair.secretKey, [1, 2, -1, -2])
    
    # Step 3: Encryption
    
    matrix1 = [ [1, 2, 3], [4, 5, 6], [7, 8, 9] ]
    matrix2 = [ [1, 2, 3], [4, 5, 6], [7, 8, 9] ]
    #matrix2 = [ [5, 6], [7, 8] ]
    encrypted_matrix1 = []
    encrypted_matrix2 = []
    
    rows1 = len(matrix1)
    cols1 = len(matrix1[0])
    rows2 = len(matrix2)
    cols2 = len(matrix2[0])
    
    for i in range(0, rows1):
        encrypted_matrix1.append([])
        for j in range(0, cols1):
            #print("ELEMENTO A ENCRIPTAR : {0}".format(matrix1[i][j]))
            plaintext = crypto_context.MakePackedPlaintext([matrix1[i][j]])
            #print("PLAINTEXT : {0}".format(plaintext))
            encrypted_matrix1[i].append(crypto_context.Encrypt(key_pair.publicKey, plaintext))
         

    for i in range(0, rows2):
        encrypted_matrix2.append([])
        for j in range(0, cols2):
            plaintext = crypto_context.MakePackedPlaintext([matrix2[i][j]])
            encrypted_matrix2[i].append(crypto_context.Encrypt(key_pair.publicKey, plaintext))
            
            
    # Step 4: Evaluation
    
    result_matrix = crypto_context.EvalMultMatrix(encrypted_matrix1, encrypted_matrix2)    
    
    # # Step 5: Decryption
    
    decrypted_product_matrix = [[None for _ in range(len(result_matrix[0]))] for _ in range(len(result_matrix))]

    for i in range(len(result_matrix)):
        for j in range(len(result_matrix[0])):
            decrypted_product_matrix[i][j] = crypto_context.Decrypt(result_matrix[i][j], key_pair.secretKey)


    # Step 6: Output results
    
    print("\nResults of homomorphic computations")
    print("\nDecrypted product matrix")
    
    for row in decrypted_product_matrix:
        print(row)
    
if __name__ == "__main__":
    main()
