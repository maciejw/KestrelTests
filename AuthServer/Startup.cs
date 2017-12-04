using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer
{

    public class X509CertificateSecretParser : ISecretParser
    {
        private readonly ILogger _Logger;
        private readonly IdentityServerOptions _Options;

        public X509CertificateSecretParser(IdentityServerOptions options, ILogger<X509CertificateSecretParser> logger)
        {
            _Options = options;
            _Logger = logger;
        }

        #region Implementation of ISecretParser

        public string AuthenticationMethod => "ClientCertificate";

        public Task<ParsedSecret> ParseAsync(HttpContext context)
        {
            _Logger.LogDebug("Start parsing for X.509 certificate");

            var certificate = context.Connection.ClientCertificate;

            if (certificate == null)
            {
                _Logger.LogDebug("Client certificate is null");
                return Task.FromResult<ParsedSecret>(null);
            }

            if (!context.Request.HasFormContentType)
            {
                _Logger.LogDebug("Content type is not a form");
                return Task.FromResult<ParsedSecret>(null);
            }

            var body = context.Request.Form;

            if (body == null)
            {
                _Logger.LogDebug("No form found");
                return Task.FromResult<ParsedSecret>(null);
            }

            var id = body["client_id"].FirstOrDefault();

            if (string.IsNullOrWhiteSpace(id))
            {
                _Logger.LogDebug("No client id found");
                return Task.FromResult<ParsedSecret>(null);
            }

            if (id.Length > _Options.InputLengthRestrictions.ClientId)
            {
                _Logger.LogError("Client ID exceeds maximum lenght.");
                return Task.FromResult<ParsedSecret>(null);
            }

            return Task.FromResult(new ParsedSecret
            {
                Id = id,
                Type = IdentityServer4.IdentityServerConstants.ParsedSecretTypes.X509Certificate,
                Credential = certificate
            });
        }

        #endregion
    }

    public class X509CertificateThumbprintSecretValidator : ISecretValidator
    {
        private readonly ILogger logger;

        public X509CertificateThumbprintSecretValidator(ILoggerFactory logger)
        {
            this.logger = logger.CreateLogger("AuthServer.X509CertificateThumbprintSecretValidator");
        }

        #region Implementation of ISecretValidator

        public Task<SecretValidationResult> ValidateAsync(IEnumerable<Secret> secrets, ParsedSecret parsedSecret)
        {

            logger.LogDebug("X509 Validation start");
            var fail = Task.FromResult(new SecretValidationResult { Success = false });
            var success = Task.FromResult(new SecretValidationResult { Success = true });

            if (parsedSecret.Type != IdentityServer4.IdentityServerConstants.ParsedSecretTypes.X509Certificate)
            {
                return fail;
            }

            var cert = parsedSecret.Credential as X509Certificate2;

            if (cert == null)
            {
                throw new ArgumentException("ParsedSecret.Credential is not an X509 Certificate");
            }

            string thumbprint = cert.Thumbprint;

            if (string.IsNullOrWhiteSpace(thumbprint))
            {
                throw new ArgumentException("ParsedSecret.Credential.Thumbprint is empty");
            }

            foreach (var secret in secrets)
            {
                if (secret.Type == IdentityServer4.IdentityServerConstants.SecretTypes.X509CertificateThumbprint)
                {
                    if (TimeConstantComparer.IsEqual(thumbprint.ToLowerInvariant(), secret.Value.ToLowerInvariant()))
                    {
                        return success;
                    }
                }
            }

            return fail;
        }

        #endregion
    }

    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddIdentityServer()
                .AddSecretParser<X509CertificateSecretParser>()
                .AddSecretValidator<X509CertificateThumbprintSecretValidator>()
                .AddSigningCredential(Program.GetServerCertificate())
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
;
            // var descriptor = services.Where(d => d.ImplementationType == typeof(ClientSecretValidator)).First();

            // services.Remove(descriptor);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            env.EnvironmentName = "Development";

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseStaticFiles();

            app.UseIdentityServer();

            app.UseMvcWithDefaultRoute();
        }
    }
}
