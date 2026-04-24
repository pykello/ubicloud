# frozen_string_literal: true

# Raised by Prog::MachineImage::{CreateVersionMetal,CreateVersionMetalFromUrl,
# DestroyVersionMetal}.assemble when the caller-provided input or current
# resource state makes the operation invalid. As a CloverError subclass it
# surfaces as a 400 InvalidRequest response, so helpers don't need to
# pre-check the same conditions in order to produce a clean API error.
class MachineImageError < CloverError
  def initialize(message)
    super(400, "InvalidRequest", message)
  end
end
