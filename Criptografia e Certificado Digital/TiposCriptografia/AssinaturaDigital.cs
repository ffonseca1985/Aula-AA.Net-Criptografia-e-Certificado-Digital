using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Criptografia_e_Certificado_Digital.TiposCriptografia
{
    public class AssinaturaDigital
    {
        //msg pra vc..
        //Chave e da mensagem(o que queremos criptografar)
        //Na assinatura Digital usamos um hash e este hash.
        //Após a assinatura não consiguimos mais descriptografar
        //Mesmo tendo a chave
        public static string Assinar(HashAlgorithm hsh, string message, byte[] key)
        {
            //MD5
            //SHA
            //Todo tipo de criptografia é feito com bytes (Nada de strings)
            var mensagemBytes = Encoding.UTF8.GetBytes(message);

            //Dado uma classe temos o método de criptografia encapsulado
            byte[] hash = hsh.ComputeHash(mensagemBytes);

            //Não podemos retornar bytes
            //Vamos retornar uma string
            return Convert.ToBase64String(hash);
        }

        //Helper para criar uma chave
        public static byte[] CreateKey()
        {
            //CRiamos uma chave de 32 bytes
            var key = new byte[32];

            //Classe auxiliadora
            using (var rgn = new RNGCryptoServiceProvider())
            {
                //Preenchendo a chave
                rgn.GetBytes(key);
            }
            //Retornando a chave preenchida
            return key;
        }
    }
}
