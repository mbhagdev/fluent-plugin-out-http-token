class MemoryCache
  VERSION = "1.0.0"

  attr_accessor :ttl_in_seconds, :cache
  private :cache

  def initialize(ttl_options)
    @cache = {}
    @ttl_in_seconds = calculate_ttl_in_seconds(ttl_options)
  end

  def get(key, &block)
    key = key.to_s
    record = cache[key]
    if record.nil? || record[:expires] < Time.now.to_i
      if block_given?
        cache[key] = {
          object: block.call,
          expires: Time.now.to_i + ttl_in_seconds
        }
      else
        return nil
      end
    end
    cache[key][:object]
  end

  def clear
    @cache = {}
  end

  private

  def calculate_ttl_in_seconds(options)
    seconds = options.fetch(:seconds, 0)
    seconds += options.fetch(:minutes, 0) * 60
    seconds += options.fetch(:hours, 0) * 60 * 60
    seconds += options.fetch(:days, 0) * 60 * 60 * 24
    fail ArgumentError.new("No duration specified for cache") if seconds.zero?
    seconds
  end

end
