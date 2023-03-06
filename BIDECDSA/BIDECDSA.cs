/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using System;
using System.Text;
using BIDHelpers.BIDECDSA.Model;
using BIDHelpers.BIDECDSA.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BIDHelpers.BIDECDSA
{
    public class BIDECDSA
    {
        /// <summary>
        /// Return private and public key pair
        /// </summary>
        /// <returns>Returns {prKey, pKey} Collection</returns>
        public static BIDKeyPair GenerateKeyPair()
        {
            var set1 = new ECKeyPairGenerator("EC");
            var keyGenParam = new KeyGenerationParameters(new SecureRandom(), 256);
            set1.Init(keyGenParam);
            var keyPair = set1.GenerateKeyPair();
            var privateBytes = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArray();
            if (privateBytes.Length != 32)
                return GenerateKeyPair();

            var EcKeyPair = new ECCKey(privateBytes, true);
            var pKey = ECCKey.GetPublicKey(EcKeyPair);
            var prKey = ECCKey.GetPrivateKey(EcKeyPair);
            return new BIDKeyPair() { prKey = prKey, pKey = pKey };
        }
        /// <summary>
        /// Returns shared key by taking prKey and pKey64 as parameters
        /// </summary>
        /// <param name="prKey"></param>
        /// <param name="pKey64"></param>
        /// <returns>Returns base 64 string</returns>
        public static string CreateSharedKey(string prKey, string pKey64)
        {
            // Generate common secret
            ECCKey PvtKey = new ECCKey(Convert.FromBase64String(prKey), true);
            var AppKeyBytes = Convert.FromBase64String(pKey64);
            byte[] updatedBytes = new byte[AppKeyBytes.Length + 1];
            updatedBytes[0] = 4;
            Array.Copy(AppKeyBytes, 0, updatedBytes, 1, AppKeyBytes.Length);
            ECCKey PubKey = new ECCKey(updatedBytes, false);
            byte[] CommonSecret = ECCKey.CalculateCommonSecret(PvtKey, PubKey);
            var ret = Convert.ToBase64String(CommonSecret);
            return ret;
        }

        /// <param name="str"></param>
        /// <param name="key64"></param>
        /// <returns>Returns base 64 encrypted string</returns>
        public static string Encrypt(string str, string key64)
        {
            byte[] nonSecretPayload = null;
            if (string.IsNullOrEmpty(str))
                throw new ArgumentException("Text required!", "text");

            var key = Convert.FromBase64String(key64);
            var base64Text = Encoding.UTF8.GetBytes(str);
            var cryptor = new Cryptor();
            var cipher = cryptor.EncryptWithKey(base64Text, key, nonSecretPayload);
            var resultB64 = Convert.ToBase64String(cipher);
            return resultB64;
        }

        /// <param name="enc_b64"></param>
        /// <param name="key64"></param>
        /// <returns>Returns decrypted plain text</returns>
        public static string Decrypt(string enc_b64, string key64)
        {
            int nonSecretPayloadLength = 0;
            if (string.IsNullOrEmpty(enc_b64))
                throw new ArgumentException("Message required!", "message");

            var key = Convert.FromBase64String(key64);
            var base64Array = Convert.FromBase64String(enc_b64);
            var cryptor = new Cryptor();
            var plainText = cryptor.DecryptWithKey(base64Array, key, nonSecretPayloadLength);
            var str = Encoding.UTF8.GetString(plainText);
            return str;
        }

    }
}
