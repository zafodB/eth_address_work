//import org.bouncycastle.crypto.params.ECDomainParameters;
//import org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory;
//import org.bouncycastle.jcajce.provider.digest.Keccak;
//import org.bouncycastle.jce.ECNamedCurveTable;
//import org.bouncycastle.jce.interfaces.ECPublicKey;
//import org.bouncycastle.jce.spec.ECParameterSpec;
//import org.bouncycastle.jce.ECNamedCurveTable;
//import org.bouncycastle.jce.interfaces.ECPrivateKey;
//import org.bouncycastle.jce.spec.ECParameterSpec;
//import org.bouncycastle.jce.spec.ECPublicKeySpec;
//import org.bouncycastle.math.ec.ECPoint;
//import org.bouncycastle.util.encoders.Base64;


import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.jcajce.provider.digest.Keccak;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.interfaces.ECPrivateKey;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;


import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;


public class main {

    public static void main(String[] args) {
        // TODO Auto-generated method stub


        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());

        Scanner sc = new Scanner(System.in);

        try {
            doCryptoStuff();
        } catch (Exception e) {
            e.printStackTrace();
        }
//        while(true) {
//        int i = 0;
//
//        while(i<1){
//
//            i++;
//            try {
//                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
//                KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
//                g.initialize(ecSpec, new SecureRandom());
//                KeyPair pair = g.generateKeyPair();
//
//                Keccak.Digest256 hashed = new Keccak.Digest256();
//
//
//                byte[] result = hashed.digest(pair.getPublic().getEncoded());
//
//                KeyFactory kf = KeyFactory.getInstance("ECDSA");
//
//                PrivateKey privK = kf.generatePrivate(new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded()));
//
//
//                System.out.println("Private key: " + privK.toString());
//                System.out.println("Public key after hash: " + byteArrayToHex(result));
//
//
//
//            }
//            catch (Exception e){
//                e.printStackTrace();
//            }


//            String input = sc.nextLine();
//
//
//            X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
//            ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
//            System.out.println("I think I'll turn mad: " + GetPublicKey(input, domain));
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
    // ecdsaSign.i  nitSign(pair.getPrivate());
    // ecdsaSign.update(plaintext.getBytes("UTF-8"));
    // byte[] signature = ecdsaSign.sign();
//    }

    static String GetPublicKey(String privKey, ECDomainParameters domain) {
        BigInteger d = new BigInteger(privKey, 16);
        //var privKeyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters(d, domain);
        org.spongycastle.math.ec.ECPoint q = domain.getG().multiply(d);
        //var pubKeyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(q, domain);
        return byteArrayToHex(q.getEncoded());
    }

    static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static void doCryptoStuff() throws Exception {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256k1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "SC");
        keyPairGenerator.initialize(ecGenSpec, new SecureRandom());
        java.security.KeyPair pair = keyPairGenerator.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();
        ECPublicKey publicKeyExpected = (ECPublicKey) pair.getPublic();

// Expected public key
//        System.out.print("Expected Public Key: " +
//                Base64.encode(publicKeyExpected.getEncoded()));

        System.out.printf("\nPrivate Key\n\n" + Hex.toHexString(privateKey.getEncoded()));
        System.out.printf("\nPrivate Key D\n\n" + privateKey.getD().toString(16));

//        System.out.printf("\nPrivate Key S\n\n" + ((ECPrivateKey) privateKey).getS());

        System.out.printf("\nPublic Key expected\n" + Hex.toHexString(publicKeyExpected.getEncoded()));
        System.out.println();


// Generate public key from private key
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "SC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

        ECPoint Q = ecSpec.getG().multiply(privateKey.getD());
        byte[] publicDerBytes = Q.getEncoded(false);

        ECPoint point = ecSpec.getCurve().decodePoint(publicDerBytes);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        ECPublicKey publicKeyGenerated = (ECPublicKey) keyFactory.generatePublic(pubSpec);

// Generated public key from private key
//        System.out.print("Generated Public Key: " +
//                Base64.encode(publicKeyGenerated.getEncoded()));

        System.out.printf("\nPublic Key generated X\n" + Hex.toHexString(publicKeyGenerated.getQ().getAffineXCoord().getEncoded()));
        System.out.printf("\nPublic Key generated Y\n" + Hex.toHexString(publicKeyGenerated.getQ().getAffineYCoord().getEncoded()));

        System.out.printf("\nPublic Key together\n" + Hex.toHexString(publicKeyGenerated.getQ().getAffineXCoord().getEncoded()) + Hex.toHexString(publicKeyGenerated.getQ().getAffineYCoord().getEncoded()));

        byte[] a = publicKeyExpected.getQ().getAffineXCoord().getEncoded();
        byte[] b = publicKeyExpected.getQ().getAffineYCoord().getEncoded();
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);

        Keccak.Digest256 hashed = new Keccak.Digest256();

        byte[] result = hashed.digest(c);

        System.out.printf("\nHashed\n" + Hex.toHexString(result));

    }

}


