# Generates the per-project detail pages at /projects/<slug>/.
#
#  * The auto-synced public repos: one page each from the data produced by
#    tools/fetch-projects.rb (_data/projects_generated.json), via the `project`
#    layout (shows the repo's rendered README).
#  * The manual "spotlight" project (Didymus, a private product): one page from
#    the `spotlight` block of _data/projects.yml, via the `spotlight` layout.

module Jekyll
  class ProjectPage < PageWithoutAFile
    def initialize(site, project)
      super(site, site.source, File.join('projects', project['slug']), 'index.html')

      data.merge!(
        'layout'    => 'project',
        'title'     => project['name'],
        'project'   => project,
        'permalink' => "/projects/#{project['slug']}/"
      )
    end
  end

  class SpotlightPage < PageWithoutAFile
    def initialize(site, spotlight)
      super(site, site.source, File.join('projects', spotlight['slug']), 'index.html')

      data.merge!(
        'layout'    => 'spotlight',
        'title'     => spotlight['name'],
        'spotlight' => spotlight,
        'permalink' => "/projects/#{spotlight['slug']}/"
      )
    end
  end

  class ProjectsPagesGenerator < Generator
    safe true
    priority :normal

    def generate(site)
      projects = site.data['projects_generated']
      unless projects.nil? || projects.empty?
        projects.each do |project|
          next if project['slug'].to_s.empty?

          site.pages << ProjectPage.new(site, project)
        end
      end

      spotlight = site.data.dig('projects', 'spotlight')
      if spotlight && !spotlight['slug'].to_s.empty?
        site.pages << SpotlightPage.new(site, spotlight)
      end
    end
  end
end
