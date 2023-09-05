# frozen_string_literal: true

class Serializers::Web::GithubInstallation < Serializers::Base
  def self.base(ins)
    {
      id: ins.id,
      name: ins.name
    }
  end

  structure(:default) do |ins|
    base(ins)
  end
end
