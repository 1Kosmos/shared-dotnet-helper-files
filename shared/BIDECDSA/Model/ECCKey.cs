/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;

namespace BIDHelpers.BIDECDSA.Model
{
    class ECCKey
    {
        public static readonly X9ECParameters _Secp256k1;
        public static readonly BigInteger HALF_CURVE_ORDER;
        public static readonly BigInteger CURVE_ORDER;
        public static readonly ECDomainParameters CURVE;
        private readonly ECKeyParameters _Key;

        private ECDomainParameters _DomainParameter;

        static ECCKey()
        {
            //using Bouncy
            _Secp256k1 = SecNamedCurves.GetByName("secp256k1");
            CURVE = new ECDomainParameters(_Secp256k1.Curve, _Secp256k1.G, _Secp256k1.N, _Secp256k1.H);
            HALF_CURVE_ORDER = _Secp256k1.N.ShiftRight(1);
            CURVE_ORDER = _Secp256k1.N;
        }

        public ECCKey(byte[] vch, bool isPrivate)
        {
            if (isPrivate)
            {
                _Key = new ECPrivateKeyParameters(new BigInteger(1, vch), DomainParameter);
            }
            else
            {
                var q = _Secp256k1.Curve.DecodePoint(vch);
                _Key = new ECPublicKeyParameters("EC", q, DomainParameter);
            }
        }

        public ECPrivateKeyParameters PrivateKey => _Key as ECPrivateKeyParameters;

        public byte[] GetPubKey(bool isCompressed)
        {
            var q = GetPublicKeyParameters().Q;
            //Pub key (q) is composed into X and Y, the compressed form only include X, which can derive Y along with 02 or 03 prepent depending on whether Y in even or odd.
            q = q.Normalize();
            var result =
                Secp256k1.Curve.CreatePoint(q.XCoord.ToBigInteger(), q.YCoord.ToBigInteger()).GetEncoded(isCompressed);
            return result;
        }

        public ECPublicKeyParameters GetPublicKeyParameters()
        {
            if (_Key is ECPublicKeyParameters)
                return (ECPublicKeyParameters)_Key;
            var q = Secp256k1.G.Multiply(PrivateKey.D);
            return new ECPublicKeyParameters("EC", q, DomainParameter);
        }

        public static byte[] CalculateCommonSecret(ECCKey PrivateKey, ECCKey PublicKey)
        {
            var agreement = new ECDHBasicAgreement();
            agreement.Init(PrivateKey.PrivateKey);
            var z = agreement.CalculateAgreement(PublicKey.GetPublicKeyParameters());

            return BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), z);
        }
        public static string GetPublicKey(ECCKey eCCKey)
        {
            byte[] PublicKey = eCCKey.GetPubKey(false);
            return Convert.ToBase64String(PublicKey, 1, PublicKey.Length - 1);
        }
        public static string GetPrivateKey(ECCKey eCCKey)
        {
            var privateBytes = eCCKey.PrivateKey.D.ToByteArray();
            return Convert.ToBase64String(privateBytes);
        }

        private static X9ECParameters Secp256k1 => _Secp256k1;

        private ECDomainParameters DomainParameter
        {
            get
            {
                if (_DomainParameter == null)
                    _DomainParameter = new ECDomainParameters(_Secp256k1.Curve, _Secp256k1.G, _Secp256k1.N, _Secp256k1.H);
                return _DomainParameter;
            }
        }

    }

}
