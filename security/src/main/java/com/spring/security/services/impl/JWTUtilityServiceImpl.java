package com.spring.security.services.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.spring.security.services.IJWTUtilityService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

@Service  // Indica que esta clase es un servicio y será administrada por Spring
public class JWTUtilityServiceImpl implements IJWTUtilityService { // Clase que implementa la interfaz IJWTUtilityService

    @Value("classpath:jwtKeys/private_key.pem") // Inyecta el valor del archivo private_key.pem como un Resource
    private Resource privateKeyResource;

    @Value("classpath:jwtKeys/public_key.pem") // Inyecta el valor del archivo public_key.pem como un Resource
    private Resource publicKeyResource;

    @Override
    public String generateJWT(Long userId) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        PrivateKey privateKey = loadPrivateKey(privateKeyResource); // Carga la clave privada desde el archivo

        JWSSigner signer = new RSASSASigner(privateKey); // Crea un firmante para firmar el JWT con la clave privada

        Date now = new Date(); // Obtiene la fecha actual
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder() // Crea un conjunto de reclamos para el JWT
                .subject(userId.toString()) // Establece el sujeto como el ID de usuario convertido a String
                .issueTime(now) // Establece la hora de emisión como la fecha actual
                .expirationTime(new Date(now.getTime() + 14400000)) // Establece la hora de expiración 4 horas después de ahora
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet); // Crea un JWT firmado usando el algoritmo RS256
        signedJWT.sign(signer); // Firma el JWT con el firmante

        return signedJWT.serialize(); // Devuelve el JWT serializado como una cadena
    }

    @Override
    public JWTClaimsSet parseJWT(String jwt) throws JOSEException, IOException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = loadPublicKey(publicKeyResource); // Carga la clave pública desde el archivo

        SignedJWT signedJWT = SignedJWT.parse(jwt); // Parsea el JWT recibido

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey); // Crea un verificador para verificar la firma del JWT
        if (!signedJWT.verify(verifier)) { // Verifica la firma del JWT
            throw new JOSEException("Invalid signature"); // Lanza una excepción si la firma es inválida
        }

        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet(); // Obtiene el conjunto de reclamos del JWT
        if (claimsSet.getExpirationTime().before(new Date())) { // Comprueba si el JWT ha expirado
            throw new JOSEException("Expired token"); // Lanza una excepción si el JWT ha expirado
        }

        return claimsSet; // Devuelve el conjunto de reclamos del JWT
    }

    private PrivateKey loadPrivateKey(Resource resource) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI())); // Lee los bytes del archivo
        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8) // Convierte los bytes a una cadena UTF-8
                .replace("-----BEGIN PRIVATE KEY-----", "") // Elimina el encabezado de la clave privada
                .replace("-----END PRIVATE KEY-----", "") // Elimina el pie de la clave privada
                .replaceAll("\\s", ""); // Elimina cualquier espacio en blanco

        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM); // Decodifica la clave en formato Base64

        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Obtiene una instancia de KeyFactory para RSA
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey)); // Genera la clave privada a partir de los bytes decodificados
    }

    private PublicKey loadPublicKey(Resource resource) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI())); // Lee los bytes del archivo
        String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8) // Convierte los bytes a una cadena UTF-8
                .replace("-----BEGIN PUBLIC KEY-----", "") // Elimina el encabezado de la clave pública
                .replace("-----END PUBLIC KEY-----", "") // Elimina el pie de la clave pública
                .replaceAll("\\s", ""); // Elimina cualquier espacio en blanco

        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM); // Decodifica la clave en formato Base64

        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Obtiene una instancia de KeyFactory para RSA
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey)); // Genera la clave pública a partir de los bytes decodificados
    }
}
