from openfhe import *
import time

def main():
    # Configuración del contexto criptográfico
    parameters = CCParamsCKKSRNS()
    parameters.SetScalingModSize(59)
    parameters.SetScalingTechnique(ScalingTechnique.FLEXIBLEAUTO)
    parameters.SetFirstModSize(60)
    parameters.SetMultiplicativeDepth(4)
    
    secret_key_dist = SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)
    parameters.SetSecurityLevel(SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)
    
    level_budget = [2, 2]
    levels_available_after_bootstrap = 4
    depth = levels_available_after_bootstrap + FHECKKSRNS.GetBootstrapDepth(level_budget, secret_key_dist)
    parameters.SetMultiplicativeDepth(depth)
    
    crypto_context = GenCryptoContext(parameters)
    crypto_context.Enable(PKESchemeFeature.PKE)
    crypto_context.Enable(PKESchemeFeature.KEYSWITCH)
    crypto_context.Enable(PKESchemeFeature.LEVELEDSHE)
    crypto_context.Enable(PKESchemeFeature.ADVANCEDSHE)
    crypto_context.Enable(PKESchemeFeature.FHE)
    
    ring_dim = crypto_context.GetRingDimension()
    num_slots = ring_dim // 2
    print(f"CKKS scheme is using ring dimension {ring_dim}\n")
    
    crypto_context.EvalBootstrapSetup(level_budget)
    
    # Generación de claves
    key_pair = crypto_context.KeyGen()
    crypto_context.EvalMultKeyGen(key_pair.secretKey)
    crypto_context.EvalBootstrapKeyGen(key_pair.secretKey, num_slots)
    
    # Tamaño de las matrices cuadradas
    num_rows_and_cols = 4
    
    # Generación automática de matrices
    value = 1.0
    matrix1 = [[(value := value + 1.25) for _ in range(num_rows_and_cols)] for _ in range(num_rows_and_cols)]
    matrix2 = [[(value := value + 2.15) for _ in range(num_rows_and_cols)] for _ in range(num_rows_and_cols)]
    
    # Cifrado de las matrices
    encrypted_matrix1 = [[crypto_context.Encrypt(key_pair.publicKey, crypto_context.MakeCKKSPackedPlaintext([matrix1[i][j]])) 
                           for j in range(num_rows_and_cols)] for i in range(num_rows_and_cols)]
    encrypted_matrix2 = [[crypto_context.Encrypt(key_pair.publicKey, crypto_context.MakeCKKSPackedPlaintext([matrix2[i][j]])) 
                           for j in range(num_rows_and_cols)] for i in range(num_rows_and_cols)]
    
    # Medición del tiempo de ejecución
    start_time = time.time()
    #result_matrix = crypto_context.EvalMultMatrixWithBootstrapping(encrypted_matrix1, encrypted_matrix2)
    result_matrix = crypto_context.EvalMultMatrix(encrypted_matrix1, encrypted_matrix2)
    end_time = time.time()
    
    # Descifrado del resultado
    decrypted_result = [[None for _ in range(len(result_matrix[0]))] for _ in range(len(result_matrix))]
    
    for i in range(len(result_matrix)):
        for j in range(len(result_matrix[0])):
            plaintext = crypto_context.Decrypt(result_matrix[i][j], key_pair.secretKey)
            decrypted_result[i][j] = plaintext.GetRealPackedValue()[0]
    
    # Impresión del resultado
    print("Resultado de la multiplicación de matrices:")
    for row in decrypted_result:
        print(row)
    
    # Impresión del tiempo de ejecución
    print(f"Tiempo de ejecución: {end_time - start_time} segundos")
    
if __name__ == "__main__":
    main()
