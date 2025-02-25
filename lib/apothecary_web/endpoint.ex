defmodule ApothecaryWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :apothecary

  @session_options [
    store: :cookie,
    key: "_apothecary_key",
    signing_salt: "sBZiBsU/"
  ]

  socket "/live", Phoenix.LiveView.Socket, websocket: [connect_info: [session: @session_options]]

  plug Plug.Static,
    at: "/",
    from: :apothecary,
    gzip: false,
    only: ~w(assets fonts images favicon.ico robots.txt)

  if code_reloading? do
    socket "/phoenix/live_reload/socket", Phoenix.LiveReloader.Socket
    plug Phoenix.LiveReloader
    plug Phoenix.CodeReloader
    plug Phoenix.Ecto.CheckRepoStatus, otp_app: :apothecary
  end

  plug Phoenix.LiveDashboard.RequestLogger,
    param_key: "request_logger",
    cookie_key: "request_logger"

  plug Plug.RequestId
  plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

  plug Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()

  plug Plug.MethodOverride
  plug Plug.Head
  plug Plug.Session, @session_options

  # Add CSP Headers
  plug :put_secure_browser_headers

  plug ApothecaryWeb.Router

  defp put_secure_browser_headers(conn, _opts) do
  nonce = :crypto.strong_rand_bytes(16) |> Base.encode64() |> binary_part(0, 22)

  conn
  |> assign(:csp_nonce, nonce)  # Store nonce in conn.assigns
  |> Plug.Conn.put_resp_header(
    "content-security-policy",
    "default-src 'self'; script-src 'self' 'nonce-#{nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  )
end
end
