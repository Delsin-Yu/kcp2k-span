// server needs to store a separate KcpPeer for each connection.
// as well as remoteEndPoint so we know where to send data to.
using System;
using System.Net;

namespace kcp2k
{
    public class KcpServerConnection : KcpPeer
    {
        public readonly EndPoint remoteEndPoint;

        // callbacks
        // even for errors, to allow liraries to show popups etc.
        // instead of logging directly.
        // (string instead of Exception for ease of use and to avoid user panic)
        //
        // events are readonly, set in constructor.
        // this ensures they are always initialized when used.
        // fixes https://github.com/MirrorNetworking/Mirror/issues/3337 and more
        protected readonly Action<KcpServerConnection> OnConnectedCallback;
        protected readonly Action<ReadOnlyMemory<byte>, KcpChannel> OnDataCallback;
        protected readonly Action OnDisconnectedCallback;
        protected readonly Action<ErrorCode, string> OnErrorCallback;
        protected readonly Action<ReadOnlyMemory<byte>> RawSendCallback;

        public KcpServerConnection(
            Action<KcpServerConnection> OnConnected,
            Action<ReadOnlyMemory<byte>, KcpChannel> OnData,
            Action OnDisconnected,
            Action<ErrorCode, string> OnError,
            Action<ReadOnlyMemory<byte>> OnRawSend,
            KcpConfig config,
            uint cookie,
            EndPoint remoteEndPoint)
                : base(config, cookie)
        {
            OnConnectedCallback = OnConnected;
            OnDataCallback = OnData;
            OnDisconnectedCallback = OnDisconnected;
            OnErrorCallback = OnError;
            RawSendCallback = OnRawSend;

            this.remoteEndPoint = remoteEndPoint;
        }

        // callbacks ///////////////////////////////////////////////////////////
        protected override void OnAuthenticated()
        {
            // once we receive the first client hello,
            // immediately reply with hello so the client knows the security cookie.
            SendHello();
            OnConnectedCallback(this);
        }

        protected override void OnData(ReadOnlyMemory<byte> message, KcpChannel channel) =>
            OnDataCallback(message, channel);

        protected override void OnDisconnected() =>
            OnDisconnectedCallback();

        protected override void OnError(ErrorCode error, string message) =>
            OnErrorCallback(error, message);

        protected override void RawSend(ReadOnlyMemory<byte> data) =>
            RawSendCallback(data);
        ////////////////////////////////////////////////////////////////////////

        // insert raw IO. usually from socket.Receive.
        // offset is useful for relays, where we may parse a header and then
        // feed the rest to kcp.
        public void RawInput(ReadOnlyMemory<byte> segment)
        {
            // ensure valid size: at least 1 byte for channel + 4 bytes for cookie
            if (segment.Length <= 5) return;

            var segmentSpan = segment.Span;
            
            // parse channel
            // byte channel = segment[0]; ArraySegment[i] isn't supported in some older Unity Mono versions
            byte channel = segmentSpan[0];

            // all server->client messages include the server's security cookie.
            // all client->server messages except for the initial 'hello' include it too.
            // parse the cookie and make sure it matches (except for initial hello).
            Utils.Decode32U(segmentSpan, 1, out uint messageCookie);

            // compare cookie to protect against UDP spoofing.
            // messages won't have a cookie until after handshake.
            // so only compare if we are authenticated.
            // simply drop the message if the cookie doesn't match.
            if (state == KcpState.Authenticated)
            {
                if (messageCookie != cookie)
                {
                    Log.Warning($"[KCP] ServerConnection: dropped message with invalid cookie: {messageCookie} expected: {cookie} state: {state}");
                    return;
                }
            }

            // parse message
            ReadOnlyMemory<byte> message = segment.Slice(1 + 4, segment.Length - 1 - 4);
            
            switch (channel)
            {
                case (byte)KcpChannel.Reliable:
                {
                    OnRawInputReliable(message);
                    break;
                }
                case (byte)KcpChannel.Unreliable:
                {
                    OnRawInputUnreliable(message);
                    break;
                }
                default:
                {
                    // invalid channel indicates random internet noise.
                    // servers may receive random UDP data.
                    // just ignore it, but log for easier debugging.
                    Log.Warning($"[KCP] ServerConnection: invalid channel header: {channel}, likely internet noise");
                    break;
                }
            }
        }
    }
}
