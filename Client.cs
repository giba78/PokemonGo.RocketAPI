﻿#region using directives

using System;
using System.Net;
using PokemonGo.RocketAPI.Enums;
using PokemonGo.RocketAPI.Extensions;
using PokemonGo.RocketAPI.HttpClient;
using PokemonGo.RocketAPI.Rpc;
using POGOProtos.Enums;
using POGOProtos.Networking.Envelopes;
using PokemonGo.RocketAPI.Helpers;

#endregion

namespace PokemonGo.RocketAPI
{
    public class Client : ICaptchaResponseHandler
    {
        public static WebProxy Proxy;

        internal readonly PokemonHttpClient PokemonHttpClient;
        public Download Download;
        public Encounter Encounter;
        public Fort Fort;
        public Inventory Inventory;
        public Rpc.Login Login;
        public Map Map;
        public Misc Misc;
        public Player Player;
        string CaptchaToken;

        public Client(ISettings settings, IApiFailureStrategy apiFailureStrategy)
        {
            Settings = settings;
            ApiFailure = apiFailureStrategy;
            Proxy = InitProxy();
            PokemonHttpClient = new PokemonHttpClient();
            Login = new Rpc.Login(this);
            Player = new Player(this);
            Download = new Download(this);
            Inventory = new Inventory(this);
            Map = new Map(this);
            Fort = new Fort(this);
            Encounter = new Encounter(this);
            Misc = new Misc(this);

            Player.SetCoordinates(Settings.DefaultLatitude, Settings.DefaultLongitude, Settings.DefaultAltitude);

            InventoryLastUpdateTimestamp = 0;

            Platform = settings.DevicePlatform.Equals("ios", StringComparison.Ordinal) ? Platform.Ios : Platform.Android;

            // We can no longer emulate Android so for now just overwrite settings with randomly generated iOS device info.
            if (Platform == Platform.Android)
            {
                DeviceInfo iosInfo = DeviceInfoHelper.GetRandomIosDevice();
                settings.DeviceId = iosInfo.DeviceId;
                settings.DeviceBrand = iosInfo.DeviceBrand;
                settings.DeviceModel = iosInfo.DeviceModel;
                settings.DeviceModelBoot = iosInfo.DeviceModelBoot;
                settings.HardwareManufacturer = iosInfo.HardwareManufacturer;
                settings.HardwareModel = iosInfo.HardwareModel;
                settings.FirmwareBrand = iosInfo.FirmwareBrand;
                settings.FirmwareType = iosInfo.FirmwareType;

                // Clear out the android fields.
                settings.AndroidBoardName = "";
                settings.AndroidBootloader = "";
                settings.DeviceModelIdentifier = "";
                settings.FirmwareTags = "";
                settings.FirmwareFingerprint = "";

                // Now set the client platform to ios
                Platform = Platform.Ios;
            }

            AppVersion = 4500;
            SettingsHash = "";

            CurrentApiEmulationVersion = new Version("0.45.0");
        }
        
        public void SetCaptchaToken(string token)
        {
            CaptchaToken = token;
        }

        public IApiFailureStrategy ApiFailure { get; set; }
        public ISettings Settings { get; }
        public string AuthToken { get; set; }

        public double CurrentLatitude { get; internal set; }
        public double CurrentLongitude { get; internal set; }
        public double CurrentAltitude { get; internal set; }
        public double CurrentAccuracy { get; internal set; }
        public float CurrentSpeed { get; internal set; }

        public AuthType AuthType => Settings.AuthType;
        internal string ApiUrl { get; set; }
        internal AuthTicket AuthTicket { get; set; }

        internal string SettingsHash { get; set; }
        internal long InventoryLastUpdateTimestamp { get; set; }
        internal Platform Platform { get; set; }
        internal uint AppVersion { get; set; }
        public long StartTime { get; set; }

        public Version CurrentApiEmulationVersion { get; set; }
        public Version MinimumClientVersion { get; set; }

        private WebProxy InitProxy()
        {
            if (!Settings.UseProxy) return null;

            var prox = new WebProxy(new Uri($"http://{Settings.UseProxyHost}:{Settings.UseProxyPort}"), false, null);

            if (Settings.UseProxyAuthentication)
                prox.Credentials = new NetworkCredential(Settings.UseProxyUsername, Settings.UseProxyPassword);

            return prox;
        }

        public bool CheckCurrentVersionOutdated()
        {
            return CurrentApiEmulationVersion < MinimumClientVersion;
        }
    }
}