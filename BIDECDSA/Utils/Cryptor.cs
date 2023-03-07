/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using System;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BIDHelpers.BIDECDSA.Utils
{
    class Cryptor
    {
        private const int KEY_BIT_SIZE = 256;
        private const int MAC_BIT_SIZE = 128;
        private const int NONCE_BIT_SIZE = 128;

        private readonly SecureRandom random;

        private static Cryptor instance;
        public static Cryptor Instance //property of this class. Create an instance if it is not created yet
        {
            get
            {
                if (instance == null)
                    instance = new Cryptor();
                return instance;
            }
        }

        public Cryptor()
        {
            random = new SecureRandom();
        }
        //decrypt with byte array
        public byte[] DecryptWithKey(byte[] message, byte[] key, int nonSecretPayloadLength = 0)
        {
            if (key == null || key.Length != KEY_BIT_SIZE / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KEY_BIT_SIZE), "key");
            if (message == null || message.Length == 0)
                throw new ArgumentException("Message required!", "message");

            using (var cipherStream = new MemoryStream(message))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                var nonSecretPayload = cipherReader.ReadBytes(nonSecretPayloadLength);
                var nonce = cipherReader.ReadBytes(NONCE_BIT_SIZE / 8);
                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(key), MAC_BIT_SIZE, nonce, nonSecretPayload);
                cipher.Init(false, parameters);
                var cipherText = cipherReader.ReadBytes(message.Length - nonSecretPayloadLength - nonce.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);
                }
                catch (InvalidCipherTextException)
                {
                    return null;
                }
                return plainText;
            }
        }

        //encrypt with byte array
        public byte[] EncryptWithKey(byte[] text, byte[] key, byte[] nonSecretPayload = null)
        {
            if (key == null || key.Length != KEY_BIT_SIZE / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KEY_BIT_SIZE), "key");

            nonSecretPayload = nonSecretPayload ?? new byte[] { };
            var nonce = new byte[NONCE_BIT_SIZE / 8];
            random.NextBytes(nonce, 0, nonce.Length);
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), MAC_BIT_SIZE, nonce, nonSecretPayload);
            cipher.Init(true, parameters);
            var cipherText = new byte[cipher.GetOutputSize(text.Length)];
            var len = cipher.ProcessBytes(text, 0, text.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    binaryWriter.Write(nonSecretPayload);
                    binaryWriter.Write(nonce);
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }
    }
}
