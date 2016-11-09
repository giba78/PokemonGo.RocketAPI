#region using directives

using System;
using System.Threading.Tasks;
using Google.Protobuf;
using PokemonGo.RocketAPI.Enums;
using PokemonGo.RocketAPI.Exceptions;
using PokemonGo.RocketAPI.Helpers;
using POGOProtos.Networking.Envelopes;
using POGOProtos.Networking.Requests;
using POGOProtos.Networking.Responses;
using System.IO;
using Newtonsoft.Json;
using System.Threading;
using POGOLib.Official.LoginProviders;
using POGOLib.Official.Net;
using POGOLib.Official.Net.Authentication.Data;

#endregion

namespace PokemonGo.RocketAPI.Rpc
{
    public delegate void GoogleDeviceCodeDelegate(string code, string uri);

    public class Login : BaseRpc
    {
        private static Semaphore ReauthenticateMutex { get; } = new Semaphore(1, 1);
        public Login(Client client) : base(client)
        {
            Client.LoginProvider = SetLoginType(client.Settings);
            Client.ApiUrl = Resources.RpcUrl;
        }

        private static ILoginProvider SetLoginType(ISettings settings)
        {
            switch (settings.AuthType)
            {
                case AuthType.Google:
                    return new GoogleLoginProvider(settings.GoogleUsername, settings.GooglePassword);
                case AuthType.Ptc:
                    return new PtcLoginProvider(settings.PtcUsername, settings.PtcPassword);
                default:
                    throw new ArgumentOutOfRangeException(nameof(settings.AuthType), "Unknown AuthType");
            }
        }

        private static AccessToken LoadAccessToken(ILoginProvider loginProvider, Client client, bool mayCache = false)
        {
            var cacheDir = Path.Combine(Directory.GetCurrentDirectory(), "Cache");
            var fileName = Path.Combine(cacheDir, $"{loginProvider.UserId}-{loginProvider.ProviderId}.json");
            
            if (mayCache)
            {
                if (!Directory.Exists(cacheDir))
                    Directory.CreateDirectory(cacheDir);

                if (File.Exists(fileName))
                {
                    var accessToken = JsonConvert.DeserializeObject<AccessToken>(File.ReadAllText(fileName));

                    if (!accessToken.IsExpired)
                    {
                        client.AccessToken = accessToken;
                        return accessToken;
                    }
                }
            }
            
            if (mayCache)
                SaveAccessToken(client.AccessToken);

            return client.AccessToken;
        }

        private static void SessionOnAccessTokenUpdated(object sender, EventArgs eventArgs)
        {
            var session = (Session)sender;

            SaveAccessToken(session.AccessToken);
        }

        private static void SaveAccessToken(AccessToken accessToken)
        {
            if (accessToken == null || string.IsNullOrEmpty(accessToken.Uid))
                return;

            var fileName = Path.Combine(Directory.GetCurrentDirectory(), "Cache", $"{accessToken.Uid}.json");

            File.WriteAllText(fileName, JsonConvert.SerializeObject(accessToken, Formatting.Indented));
        }

        public static async Task Reauthenticate(Client client)
        {
            ReauthenticateMutex.WaitOne();
            if (null == client.AccessToken || client.AccessToken.IsExpired)
            {
                AccessToken accessToken = null;
                var tries = 0;
                while (accessToken == null)
                {
                    try
                    {
                        accessToken = await client.LoginProvider.GetAccessToken();
                    }
                    catch (Exception)
                    {
                        //Logger.Error($"Reauthenticate exception was catched: {exception}");
                    }
                    finally
                    {
                        if (accessToken == null)
                        {
                            var sleepSeconds = Math.Min(60, ++tries * 5);
                            //Logger.Error($"Reauthentication failed, trying again in {sleepSeconds} seconds.");
                            await Task.Delay(TimeSpan.FromMilliseconds(sleepSeconds * 1000));
                        }
                    }
                }
                client.AccessToken = accessToken;
                SaveAccessToken(client.AccessToken);
            }
            ReauthenticateMutex.Release();
        }

        public async Task DoLogin()
        {
            Login.LoadAccessToken(Client.LoginProvider, Client, true);
            Client.StartTime = Utils.GetTime(true);

            await
                FireRequestBlock(CommonRequest.GetDownloadRemoteConfigVersionMessageRequest(Client))
                    .ConfigureAwait(false);

            await FireRequestBlockTwo().ConfigureAwait(false);
        }
        
        private async Task FireRequestBlock(Request request)
        {
            var requests = CommonRequest.FillRequest(request, Client);

            var serverRequest = await GetRequestBuilder().GetRequestEnvelope(requests, true);
            var serverResponse = await PostProto<Request>(serverRequest);

            if (!string.IsNullOrEmpty(serverResponse.ApiUrl))
                Client.ApiUrl = "https://" + serverResponse.ApiUrl + "/rpc";

            if (serverResponse.AuthTicket != null)
                Client.AccessToken.AuthTicket = serverResponse.AuthTicket;

            switch (serverResponse.StatusCode)
            {
                case ResponseEnvelope.Types.StatusCode.InvalidAuthToken:
                    Client.AccessToken.Expire();
                    await Login.Reauthenticate(Client);
                    await FireRequestBlock(request);
                    return;
                case ResponseEnvelope.Types.StatusCode.Redirect:
                    // 53 means that the api_endpoint was not correctly set, should be at this point, though, so redo the request
                    await FireRequestBlock(request);
                    return;
                case ResponseEnvelope.Types.StatusCode.BadRequest:
                    // Your account may be banned! please try from the official client.
                    throw new LoginFailedException("Your account may be banned! please try from the official client.");
                case ResponseEnvelope.Types.StatusCode.Unknown:
                    break;
                case ResponseEnvelope.Types.StatusCode.Ok:
                    break;
                case ResponseEnvelope.Types.StatusCode.OkRpcUrlInResponse:
                    break;
                case ResponseEnvelope.Types.StatusCode.InvalidRequest:
                    break;
                case ResponseEnvelope.Types.StatusCode.InvalidPlatformRequest:
                    break;
                case ResponseEnvelope.Types.StatusCode.SessionInvalidated:
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }

            var responses = serverResponse.Returns;
            if (responses != null)
            {
                var checkChallengeResponse = new CheckChallengeResponse();
                if (2 <= responses.Count)
                {
                    checkChallengeResponse.MergeFrom(responses[1]);

                    CommonRequest.ProcessCheckChallengeResponse(Client, checkChallengeResponse);
                }

                var getInventoryResponse = new GetInventoryResponse();
                if (4 <= responses.Count)
                {
                    getInventoryResponse.MergeFrom(responses[3]);

                    CommonRequest.ProcessGetInventoryResponse(Client, getInventoryResponse);
                }

                var downloadSettingsResponse = new DownloadSettingsResponse();
                if (6 <= responses.Count)
                {
                    downloadSettingsResponse.MergeFrom(responses[5]);

                    CommonRequest.ProcessDownloadSettingsResponse(Client, downloadSettingsResponse);
                }
            }
        }

        public async Task FireRequestBlockTwo()
        {
            await FireRequestBlock(CommonRequest.GetGetAssetDigestMessageRequest(Client));
        }
    }
}