# Generates one page per project at /projects/<slug>/ from the data produced by
# tools/fetch-projects.rb (_data/projects_generated.json). Each page shows the
# repo's rendered README via the `project` layout.

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

  class ProjectsPagesGenerator < Generator
    safe true
    priority :normal

    def generate(site)
      projects = site.data['projects_generated']
      return if projects.nil? || projects.empty?

      projects.each do |project|
        next if project['slug'].to_s.empty?

        site.pages << ProjectPage.new(site, project)
      end
    end
  end
end
