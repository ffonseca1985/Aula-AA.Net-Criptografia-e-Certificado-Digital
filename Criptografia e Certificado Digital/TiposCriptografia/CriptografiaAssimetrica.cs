using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Criptografia_e_Certificado_Digital.TiposCriptografia
{
    public class CriptografiaAssimetrica
    {
        //Criptografar com a chave privada
        //Descriptografar com a chave publica
        //O certificado já tem

        //formato X509Certificate2

        //Carregar o certificado e suas chaves
        //Certificado => X509Store

        private readonly X509Certificate2 _certificado;
        public CriptografiaAssimetrica(X509Certificate2 certificado)
        {
            _certificado = certificado;
        }

        public static CriptografiaAssimetrica Carregar(string nome,
            StoreName name,
            StoreLocation localLocation)
        {
            //Carregando os dados do store.
            var store = new X509Store(name, localLocation);
            store.Open(OpenFlags.ReadOnly);

            //Estou pegando todos os certificados que estão na máquina.
            var certificados = store.Certificates.OfType<X509Certificate2>().ToList();

            //Filtrando o que eu quero
            var certificado = certificados.FirstOrDefault(
                c => c.SubjectName != null && c.SubjectName.Name == nome);

            return new CriptografiaAssimetrica(certificado);
        }

        public string Encrypto(string texto)
        {
            //AsymmetricAlgorithm
            //A partir da chave definimos um tipo de criptografia simetrica
            var algoritmoAssimetrico = (RSACryptoServiceProvider)_certificado.PublicKey.Key;
            var textoBytes = Encoding.UTF8.GetBytes(texto);
            //Ciframos o texto e colocamos que retorna bites
            var textoCrit = algoritmoAssimetrico.Encrypt(textoBytes, true);
            //Converteu em texto e em base 64
            return Convert.ToBase64String(textoCrit);
        }

        public string DeCrypto(string texto)
        {
            //AsymmetricAlgorithm
            //Como a criptografia foi criada a partir da chave publica
            //Só podemos decriptografar com a chave privada

            //Obs: Da mesma forma se criptografarmos com a chave privada
            //Só podemos decriptgrafar com a chave pública
            var algoritmoAssimetrico = (RSACryptoServiceProvider)_certificado.PrivateKey;

            var textoBase64 = Convert.FromBase64String(texto);

            //Ciframos o texto e colocamos que retorna bites
            var textoCrit = algoritmoAssimetrico.Decrypt(textoBase64, true);
            //Converteu em texto e em base 64
            return Encoding.UTF8.GetString(textoCrit);
        }
    }
}
