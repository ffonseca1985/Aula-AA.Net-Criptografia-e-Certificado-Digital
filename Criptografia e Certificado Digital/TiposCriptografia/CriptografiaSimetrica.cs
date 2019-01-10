using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Criptografia_e_Certificado_Digital.TiposCriptografia
{
    public class CriptografiaSimetrica
    {
        //Precisamos de uma chave
        private readonly byte[] _key;

        //Precisamos de um vetor de inicialização
        private readonly byte[] _vetorInicializacao;

        //Uma classe abstrato que contém os metodos de criptografia
        //Simetrica
        private readonly SymmetricAlgorithm _provider;

        //Inicializar o tipo de criptografia
        public CriptografiaSimetrica(SymmetricAlgorithm provider)
        {
            //1 bite = 8 bites
            //Definimos um tamanho para o vetor de inicialização
            _vetorInicializacao = new byte[provider.BlockSize / 8];

            //Definimos um tamanho para a chave
            _key = new byte[provider.KeySize / 8];

            //Definimos a chave
            //Gerando algumas chave dinamicas
            using (var rgn = new RNGCryptoServiceProvider())
            {
                rgn.GetBytes(_vetorInicializacao);
                rgn.GetBytes(_key);
            }

            _provider = provider;
        }

        public string Crypto(string texto)
        {
            //Tranformou o texto em Bytes
            var textoBytes = Encoding.UTF8.GetBytes(texto);

            //Criptografia:
            //Transform => elemento(key, vetor) + texto = Criptografia
            var transform = CriptoTransform(textoBytes,
                _provider.CreateEncryptor(_key, _vetorInicializacao));

            //retornou uma string
            return Convert.ToBase64String(transform);
        }

        public string Decripto(string textoCriptografado)
        {
            var textoB64 = Convert.FromBase64String(textoCriptografado);

            var transform = CriptoTransform(textoB64,
                _provider.CreateDecryptor(_key, _vetorInicializacao));

            return Encoding.UTF8.GetString(transform);
        }

        private static byte[] CriptoTransform(byte[] texto, ICryptoTransform tranform)
        {
            //Criando um buffer em memória
            using (var buffer = new MemoryStream())
            {
                //colocamos o transform no buffer
                //Juntando a chave e o texto
                using (var stream = new CryptoStream(buffer,
                    tranform, CryptoStreamMode.Write))
                {
                    stream.Write(texto, 0, texto.Length);

                    stream.FlushFinalBlock();
                    return buffer.ToArray();
                }
            }
        }
    }
}
