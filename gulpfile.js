const gulp = require("gulp");
const ts = require('gulp-typescript');
const babel = require('gulp-babel');
const del = require('del');

const tsProject = ts.createProject('./tsconfig.json');

// Clean dist folder
gulp.task('clean', () => del('dist'));

// Build js and css
gulp.task('build:js', () => gulp.src('src/static/js/*')
  .pipe(babel({
    presets: [[
      "@babel/preset-env",
      {
        useBuiltIns: "entry",
        corejs: 3,
        targets: {
          esmodules: true,
        }
      }
    ]]
  }))
  .pipe(gulp.dest('dist/static/js')));

gulp.task('build:ts', () => tsProject.src()
  .pipe(tsProject())
  .pipe(gulp.dest('dist')));

gulp.task('build', gulp.parallel(
  'build:js',
  'build:ts'
));

// Copy files
gulp.task('copy:css', () => gulp.src('src/static/css/**')
  .pipe(gulp.dest('dist/static/css')));

gulp.task('copy:favicon', () => gulp.src('src/static/favicon.ico')
  .pipe(gulp.dest('dist/static')));

gulp.task('copy:default-config', () => gulp.src('src/config/default.json')
  .pipe(gulp.dest('dist/config')));

gulp.task('copy:templates', () => gulp.src('src/templates/**')
  .pipe(gulp.dest('dist/templates')));

gulp.task('copy:emails', () => gulp.src('src/emails/**')
  .pipe(gulp.dest('dist/email')));

gulp.task('copy', gulp.parallel(
  'copy:css',
  'copy:favicon',
  'copy:default-config',
  'copy:templates',
  'copy:emails'
));

// Default task
gulp.task('default', gulp.series('clean', 'build', 'copy'));
