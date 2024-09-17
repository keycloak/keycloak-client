package org.keycloak.testsuite.util;

import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.KeysMetadataRepresentation;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.function.Predicate;
import java.util.stream.Stream;


/**
 * @author mhajas
 */
public class KeyUtils {

    public static KeyPair generateEdDSAKey(String curve) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = CryptoIntegration.getProvider().getKeyPairGen(curve);
        return kpg.generateKeyPair();
    }

    public static SecretKey generateSecretKey(String algorithm, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGen = KeyGenerator.getInstance(JavaAlgorithm.getJavaAlgorithm(algorithm), BouncyIntegration.PROVIDER);
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    public static PublicKey publicKeyFromString(String key) {
        try {
            KeyFactory kf = CryptoIntegration.getProvider().getKeyFactory(KeyType.RSA);
            byte[] encoded = Base64.getDecoder().decode(key);
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey privateKeyFromString(String key) {
        try {
            KeyFactory kf = CryptoIntegration.getProvider().getKeyFactory(KeyType.RSA);
            byte[] encoded = Base64.getDecoder().decode(key);
            return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeysMetadataRepresentation.KeyMetadataRepresentation getActiveEncryptionKey(KeysMetadataRepresentation keys, String algorithm) {
        for (KeysMetadataRepresentation.KeyMetadataRepresentation k : keys.getKeys()) {
            if (k.getAlgorithm().equals(algorithm) && KeyStatus.valueOf(k.getStatus()).isActive() && KeyUse.ENC.equals(k.getUse())) {
                return k;
            }
        }
        throw new RuntimeException("Active key not found");
    }

    public static KeysMetadataRepresentation.KeyMetadataRepresentation findActiveSigningKey(RealmResource realm) {
        return findRealmKeys(realm, rep -> rep.getPublicKey() != null && KeyStatus.valueOf(rep.getStatus()).isActive() && KeyUse.SIG.equals(rep.getUse()))
                .findFirst()
                .orElse(null);
    }

    public static KeysMetadataRepresentation.KeyMetadataRepresentation findActiveSigningKey(RealmResource realm, String alg) {
        return findRealmKeys(realm, rep -> rep.getPublicKey() != null && KeyStatus.valueOf(rep.getStatus()).isActive() && KeyUse.SIG.equals(rep.getUse()) && alg.equals(rep.getAlgorithm()))
                .findFirst()
                .orElse(null);
    }

    public static KeysMetadataRepresentation.KeyMetadataRepresentation findActiveEncryptingKey(RealmResource realm, String alg) {
        return findRealmKeys(realm, rep -> rep.getPublicKey() != null && KeyStatus.valueOf(rep.getStatus()).isActive() && KeyUse.ENC.equals(rep.getUse()) && alg.equals(rep.getAlgorithm()))
                .findFirst()
                .orElse(null);
    }

    public static Stream<KeysMetadataRepresentation.KeyMetadataRepresentation> findRealmKeys(RealmResource realm, Predicate<KeysMetadataRepresentation.KeyMetadataRepresentation> filter) {
        return realm.keys().getKeyMetadata().getKeys().stream().filter(filter);
    }

}
