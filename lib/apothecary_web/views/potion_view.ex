defmodule ApothecaryWeb.PotionView do
  use ApothecaryWeb, :view

  def print_cents(c) do
    c / 100
  end
end
