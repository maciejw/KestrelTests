using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Abstractions.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Server
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            TaskScheduler.UnobservedTaskException += (sender, e) =>
            {
                Console.WriteLine("Unobserved exception: {0}", e.Exception);
            };

            var configuration = new ConfigurationBuilder()
                .AddJsonFile("logging.json")
                .AddEnvironmentVariables()
                .Build();

            var host = new WebHostBuilder()
                .UseConfiguration(configuration)
                .ConfigureLogging((context, factory) =>
                {
                    factory
                        .AddConfiguration(context.Configuration.GetSection("Logging"))
                        .AddConsole();
                })
                .UseKestrel(options =>
                {
                    var store = new X509Store(StoreName.My, StoreLocation.CurrentUser, OpenFlags.MaxAllowed);

                    var certificateCollection = store.Certificates.Find(X509FindType.FindByThumbprint, "6710526cdf6a07fe918863dc042a4c5581bb0579", false);



                    // Run callbacks on the transport thread
                    options.ApplicationSchedulingMode = SchedulingMode.Inline;
                    options.Listen(IPAddress.Loopback, 5001, listenOptions =>
                    {
                        HttpsConnectionAdapterOptions httpsOptions = new HttpsConnectionAdapterOptions();
                        httpsOptions.ServerCertificate = certificateCollection.Cast<X509Certificate2>().First();
                        httpsOptions.ClientCertificateMode = ClientCertificateMode.NoCertificate;
                        httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;

                        listenOptions.UseHttps(httpsOptions);
                        listenOptions.UseConnectionLogging();
                    });
                    options.Listen(IPAddress.Loopback, 5002, listenOptions =>
                    {
                        HttpsConnectionAdapterOptions httpsOptions = new HttpsConnectionAdapterOptions();
                        httpsOptions.ServerCertificate = certificateCollection.Cast<X509Certificate2>().First();
                        httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                        httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                        listenOptions.UseHttps(httpsOptions);
                        listenOptions.UseConnectionLogging();
                    });
                })
                .UseStartup<Startup>()
                .Build();

            return host;
        }
    }
}
