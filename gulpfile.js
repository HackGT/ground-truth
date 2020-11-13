const gulp = require("gulp");
const ts = require('gulp-typescript');
const babel = require('gulp-babel');
const del = require('del');

const tsProject = ts.createProject('./tsconfig.json');

// Clean dist folder
gulp.task('clean', function () {
    return del('dist');
});

// Build js and css
gulp.task('build:js', () => {
    return gulp.src('src/static/js/*')
        .pipe(babel({
            presets: ['@babel/env']
        }))
        .pipe(gulp.dest('dist/static/js'))
});

gulp.task('build:ts', () => {
    return tsProject.src()
        .pipe(tsProject())
        .pipe(gulp.dest('dist'));
});

gulp.task('build', gulp.parallel(
    'build:js',
    'build:ts'
));

// Copy files
gulp.task('copy:css', function () {
    return gulp.src('src/static/css/**')
        .pipe(gulp.dest('dist/static/css'));
});

gulp.task('copy:templates', function () {
    return gulp.src('src/templates/**')
        .pipe(gulp.dest('dist/templates'));
});

gulp.task('copy:emails', function () {
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
