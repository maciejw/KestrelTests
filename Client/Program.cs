using System;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityModel.Client;

namespace Client
{
    class Program
    {
        static async Task MainAsync(string[] args)
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser, OpenFlags.MaxAllowed);

            var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, "70238415687f346eade626bcae1dd7b5dd4e0ada", false);

            var handler = new HttpClientHandler();

            handler.ClientCertificates.AddRange(certificate);
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;


            var disco = new DiscoveryClient("https://localhost:5000", handler);

            var discoveryResponse = await disco.GetAsync();

            if (discoveryResponse.IsError)
            {
                System.Console.WriteLine($"Status {discoveryResponse.StatusCode} Error {discoveryResponse.Error}");
                return;
            }

            var tokenClient = new TokenClient(discoveryResponse.TokenEndpoint, "client", handler);

            var tokenResponse = await tokenClient.RequestClientCredentialsAsync("api1");

            if (tokenResponse.IsError)
            {
                Console.WriteLine(tokenResponse.Error);
                return;
            }

            Console.WriteLine($"Token expires in {tokenResponse.ExpiresIn}");
            Console.WriteLine("\n\n");

            var client = new HttpClient()
            {
                BaseAddress = new Uri("https://localhost:5001")
            };

            client.SetBearerToken(tokenResponse.AccessToken);

            Stopwatch watch = new Stopwatch();
            watch.Start();
            for (int i = 0; i < 100; i++)
            {
                var response = await client.GetAsync("/api");
                response.EnsureSuccessStatusCode();

                Console.WriteLine($"{response.StatusCode} {watch.ElapsedMilliseconds}");
                await Task.Delay(100);
            }
            watch.Stop();
        }
        static void Main(string[] args)
        {
            MainAsync(args).GetAwaiter().GetResult();
        }
    }
}
