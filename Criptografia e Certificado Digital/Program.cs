using Criptografia_e_Certificado_Digital.TiposCriptografia;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Criptografia_e_Certificado_Digital
{
    public class Program
    {
        static void Main(string[] args)
        {
            //Modelo de criptografia simetrico
            //Rijndael => é um metodo de critografia que usa uma chave de até 256 bits
            //using (var rij = new RijndaelManaged())
            using (var rij = new AesCryptoServiceProvider())
            {
                const string texto = "Curso de Autenticação";
                var critp = new CriptografiaSimetrica(rij);
                var textoCriptografado = critp.Crypto(texto);
                var textoDecriptografado = critp.Decripto(textoCriptografado);
            }

            //Assinatura
            //using (var des = DES.Create())
            using (var md5 = MD5.Create())
            {
                //O texto para criar o hash
                const string texto = "Curso de Autenticação";
                //Criando uma chave
                var chave = AssinaturaDigital.CreateKey();
                // Criando o Hash
                var hash = AssinaturaDigital.Assinar(md5, texto, chave);
                // Se for modificado qualquer coisa o hash muda completamente
                var hash2 = AssinaturaDigital.Assinar(md5, texto + "s", chave);
            }

            //Criptografia assimetrica
            //Para criar um certificado, basta ir até o console do visual studio
            //C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\Shortcuts
            //makecert -sr LocalMachine -ss My -a sha1 -n CN=Carlos -sky exchange -pe
            const string mensagem = "LGroup Treinamentos";
            //Local(store) aonde iremos pegar o certificados
            var name = StoreName.My;
            //tipo de local
            var localLocation = StoreLocation.LocalMachine;
            //O nome do cerficado e o local na máquina
            var classe = CriptografiaAssimetrica.Carregar("CN=Carlos", name, localLocation);
            //Criptografando com a chave publica
            var textoCripto = classe.Encrypto(mensagem);
            //Decriptografando com a chave privada
            var textoDecripto = classe.DeCrypto(textoCripto);
            //Da mesma forma podemos decriptografar com a chave privada
            //E decriptografar com a chave pública

            Console.ReadKey();
        }

    }
}
