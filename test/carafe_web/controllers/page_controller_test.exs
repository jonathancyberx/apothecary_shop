defmodule ApothecaryWeb.PotionControllerTest do
  use ApothecaryWeb.ConnCase

  test "GET /", %{conn: conn} do
    conn = get(conn, "/")
    assert html_response(conn, 200) =~ "Apothecary"
  end
end
