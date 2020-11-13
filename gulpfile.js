const gulp = require("gulp");
const ts = require('gulp-typescript');
const babel = require('gulp-babel');
const del = require('del');
const gulpif = require('gulp-if');
const { reportBuild } = require('gulp-bugsnag');
const fs = require("fs");
const path = require("path");

const VERSION_NUMBER = JSON.parse(fs.readFileSync(path.resolve(__dirname, "package.json"), "utf8")).version;
const tsProject = ts.createProject('./tsconfig.json');

// Clean dist folder
gulp.task('clean', () => {
    return del('dist');
});

// Build js and css
gulp.task('build:js', () => {
    return gulp.src('src/static/js/*')
        .pipe(babel({
            presets: ['@babel/env']
        }))
        .pipe(gulp.dest('dist/static/js'));
});

// If production environment and bugsnag api key, report build to bugsnag
gulp.task('build:ts', () => {
    return tsProject.src()
        .pipe(tsProject())
        .pipe(gulp.dest('dist'))
        .pipe(gulpif(process.env.NODE_ENV == "production" && process.env.BUGSNAG, reportBuild({
            apiKey: process.env.BUGSNAG,
            appVersion: VERSION_NUMBER,
            releaseStage: "production",
            autoAssignRelease: true
        })));
});

gulp.task('build', gulp.parallel(
    'build:js',
    'build:ts'
));

// Copy files
gulp.task('copy:css', () => {
    return gulp.src('src/static/css/**')
        .pipe(gulp.dest('dist/static/css'));
});

gulp.task('copy:templates', () => {
    return gulp.src('src/templates/**')
        .pipe(gulp.dest('dist/templates'));
});

gulp.task('copy:emails', () => {
    return gulp.src('src/emails/**')
        .pipe(gulp.dest('dist/email'));
});

gulp.task('copy', gulp.parallel(
    'copy:css',
    'copy:templates',
    'copy:emails'
));

// Default task
gulp.task('default', gulp.series('clean', 'build', 'copy'));
