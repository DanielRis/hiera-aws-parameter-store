class Hiera
  module Backend
    class Aws_parameter_store_backend
      def initialize(cache=nil)
        require 'aws-sdk'
        Hiera.debug("AWS Parameter Store backend starting")

        max_results = Config[:aws_parameter_store][:max_results] || 50
        access_key = Config[:aws_parameter_store][:access_key] || ''
        secret_key = Config[:aws_parameter_store][:secret_key] || ''
        region = Config[:aws_parameter_store][:region] || 'us-east-1'

        Hiera.debug("Creating AWS client")
        @ssm_client = Aws::SSM::Client.new(region: region, credentials: Aws::Credentials.new(access_key, secret_key))

        @key_cache = read_parameter_keys_from_aws_parameter_store(max_results)
        Hiera.debug("Key Cache=#{@key_cache}")
      end

      def lookup(key, scope, order_override, resolution_type)
        answer = nil

        Hiera.debug("Looking up #{key} in AWS Parameter Store backend")
        if @key_cache.include?(key)
          # Extra logging that we found the key. This can be outputted
          # multiple times if the resolution type is array or hash but that
          # should be expected as the logging will then tell the user ALL the
          # places where the key is found.
          Hiera.debug("Found #{key}")

          # for array resolution we just append to the array whatever
          # we find, we then goes onto the next file and keep adding to
          # the array
          #
          # for priority searches we break after the first found data item
          new_answer = Backend.parse_answer(read_parameter_value_from_aws_parameter_store(key), scope)
          case resolution_type
          when :array
            raise Exception, "Hiera type mismatch: expected Array and got #{new_answer.class}" unless new_answer.kind_of? Array or new_answer.kind_of? String
            answer ||= []
            answer << new_answer
          when :hash
            raise Exception, "Hiera type mismatch: expected Hash and got #{new_answer.class}" unless new_answer.kind_of? Hash
            answer ||= {}
            answer = Backend.merge_answer(new_answer,answer)
          else
            answer = new_answer
          end
        end

        return answer
      end

      private

      def read_parameter_value_from_aws_parameter_store(key)
        Hiera.debug("Looking up value for parameter #{key}'s in AWS Parameter Store backend")
        presp = @ssm_client.get_parameter({
          name: key,
          with_decryption: true,
        })
        if presp.parameter.type == "StringList"
          raw_string_list = presp.parameter.value
          return_value = raw_string_list.split(",")
        else
          return_value = presp.parameter.value
        end
        return return_value
      end

      def read_parameter_keys_from_aws_parameter_store(max_results)
        Hiera.debug("Obtaining parameter keys from AWS Parameter Store")
        parameter_keys = []
        next_token = nil
        loop do
          resp = @ssm_client.describe_parameters({
            max_results: max_results,
            next_token: next_token
            })
          resp.parameters.each do |parameter|
            parameter_keys.push(parameter.name)
          end
          next_token = resp.next_token
          break unless next_token
        end
        return parameter_keys
      end
    end
  end
end
