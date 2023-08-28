defmodule Apothecary.Repo do
  use Ecto.Repo,
    otp_app: :apothecary,
    adapter: Ecto.Adapters.Postgres

  use Paginator
end
