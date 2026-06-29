# frozen_string_literal: true

source "https://rubygems.org"

gem "jekyll-theme-chirpy", "~> 7.5"

# Multi-language (EN/ES) support. Lives in the :jekyll_plugins group so Jekyll
# auto-requires it during the build.
group :jekyll_plugins do
  gem "jekyll-polyglot", "~> 1.9"
end

gem "html-proofer", "~> 5.0", group: :test

platforms :windows, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.2.0", :platforms => [:windows]
