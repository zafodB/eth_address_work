import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.symmetric.ARC4;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;


public class main {

    public static void main(String[] args) {
        // TODO Auto-generated method stub


        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


        Scanner sc = new Scanner(System.in);

        while (true) {
            X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
            ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());

            BigInteger d = new BigInteger(sc.nextLine().toString().getBytes());
            ECPoint q = domain.getG().multiply(d);

            ECPublicKeyParameters publicParams = new ECPublicKeyParameters(q, domain);
            System.out.println(byteArrayToHex(publicParams.getQ().getEncoded()));
        }
//        try {
//            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
//            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
//
//            keyGen.initialize(ecSpec, new SecureRandom());
////
//
//            KeyPair pair = keyGen.generateKeyPair();
//            PrivateKey priv = pair.getPrivate();
//            PublicKey pub = pair.getPublic();
//
//            // to recover the key
//            KeyFactory kf = KeyFactory.getInstance("ECDSA");
//
//            PrivateKey prv_recovered = kf.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
//            PublicKey pub_recovered = kf.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
//
//
////                System.out.println("Private Key: \n" + prv_recovered.toString());
////                System.out.println("Public Key: \n" + pub_recovered.toString());
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        // KeyPair pair = GenerateKeys();
        // Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        // ecdsaSign.initSign(pair.getPrivate());
        // ecdsaSign.update(plaintext.getBytes("UTF-8"));
        // byte[] signature = ecdsaSign.sign();
    }

    static String GetPublicKey(String privKey, ECDomainParameters domain) {
        BigInteger d = new BigInteger(privKey, 16);
        ECPrivateKeyParameters privKparams = new ECPrivateKeyParameters(d, domain);
        org.bouncycastle.math.ec.ECPoint q = domain.getG().multiply(d);
        ECPublicKeyParameters pubparams = new ECPublicKeyParameters(q, domain);
        return byteArrayToHex(q.getEncoded());
    }

    static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }


}

3a4ab22da00990300828b0f988ecc450ad9693147b341db235f007da56d2446d7e3cde216481b4532e3ab3c219d91945262d6136880f0707e66b1dd71e436f57

        3b4606f53ea8bc10272a9a5de17380465c95674b9a881b0b1980222e7f4b1d3f

        0x77443347472554D910471f6f817803FEC62B1cF7

