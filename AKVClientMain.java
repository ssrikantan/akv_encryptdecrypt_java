package javaclientakv;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.crypto.Cipher;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.KeyOperationResult;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyEncryptionAlgorithm;


public class AKVClientMain {

	// This App ID of the Application registered in Azure AD - reqd by this program to use Azure Key Vault APIs
	private static String clientId = "{Replace this with the App ID of your application in Azure AD}";
	//The secret generated corresponding to the App ID above, in Azure AD
	private static String clientKey = "{Replace this with the secret corresponding to the above App ID in Azure AD}";
	
	public static void main(String[] args){
		
		try {
		// Creates the Key Vault client.
		KeyVaultCredentialsImpl credentials = new KeyVaultCredentialsImpl();
		KeyVaultClient kv = new KeyVaultClient(credentials);

		String vaultUri = "https://{Replace this with your Azure Key vault Name}.vault.azure.net";
		String keyUri = vaultUri + "/keys/{Replace this with your Key Name}/";
		
		// encrypt data locally using the Certificate on the Machine
		byte[] cipherText= EncryptDataLocally("this is a test data");
		System.out.println("Message encryption completed ....");
		
		// Performs the decrypt operation using Azure Key Vault APIs
		KeyOperationResult decryptResult = kv.decrypt(keyUri, JsonWebKeyEncryptionAlgorithm.RSA1_5, cipherText);
		//KeyOperationResult decryptResult = kv.decrypt(keyUri, JsonWebKeyEncryptionAlgorithm.RSA_OAEP, cipherText);

		// Shows the result in the console as a byte array.
		byte[] plainText = decryptResult.result();
		
		// Shows the result in the console as a string, assuming each byte is a character.
		String plainTextStr = new String(plainText, "ISO-8859-1");
		System.out.println("Decrypted this message :"+plainTextStr);
		}
		catch (Exception e) {
			// TODO: handle exception - 
			System.out.println("Error>> "+e.getMessage());
		}

		System.out.println("Finished!");
	}
	
	
	
	private static byte[] EncryptDataLocally(String message)throws Exception
	{
		// The Certificate containing the CER content could be downloaded from Azure Key Vault (in a Dev environment), or 
		// obtained from a CA after signing. This would be imported into the Certificate store on the machine where
		// the content would be encrypted
		// This has been described here https://blogs.msdn.microsoft.com/srikantan/2017/08/19/working-with-azure-key-vault-certificates-for-secure-exchange-of-data/
		
		//Read the X509 Certificate from the local machine to encrypt the data with
		//Ideally, this should be read from the Certificate Store/KeyStore on the machine
		//Reading from a file directly for simplicity here
		InputStream inStream = new FileInputStream("C:\\Users\\sansri\\eclipse-workspace\\javaclientakv\\programcert.crt");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
		inStream.close();
		PublicKey rsaPublicKey = cert.getPublicKey();

		Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
		//Cipher encryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
		//Cipher encryptCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");

		encryptCipher.init(Cipher.ENCRYPT_MODE,rsaPublicKey);
		byte[] messageACrypter = message.getBytes();
		byte[] messageCrypte = encryptCipher.doFinal(messageACrypter);
		return messageCrypte;
	}
	
	static class KeyVaultCredentialsImpl extends KeyVaultCredentials {

		@Override
		public String doAuthenticate(String authorization, String resource, String scope) {
			try {
				AuthenticationResult authResult = getAccessToken(authorization, resource);
				return authResult.getAccessToken();
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private AuthenticationResult getAccessToken(String authorization, String resource) throws Exception {

			AuthenticationResult result = null;
			ExecutorService service = null;
			try {
				service = Executors.newFixedThreadPool(1);
				AuthenticationContext context = new AuthenticationContext(authorization, false, service);
				Future<AuthenticationResult> future = null;
				ClientCredential credentials = new ClientCredential(clientId, clientKey);
				future = context.acquireToken(resource, credentials, null);
				result = future.get();
			} finally {
				service.shutdown();
			}

			if (result == null) {
				throw new RuntimeException("authentication result was null");
			}

			return result;
		}
	}

}
