const gulp = require("gulp");
const ts = require('gulp-typescript');
const babel = require('gulp-babel');
const del = require('del');

const tsProject = ts.createProject('./tsconfig.json');

// Clean dist folder
gulp.task('clean', () => {
    return del('dist');
});

// Build js and css
gulp.task('build:js', () => {
    return gulp.src('src/static/js/*')
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
        .pipe(gulp.dest('dist/static/js'));
});

gulp.task('build:ts', () => {
    return tsProject.src()
        .pipe(tsProject())
        .pipe(gulp.dest('dist'))
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

gulp.task('copy:favicon', () => {
    return gulp.src('src/static/favicon.ico')
        .pipe(gulp.dest('dist/static'));
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
    'copy:favicon',
    'copy:templates',
    'copy:emails'
));

// Default task
gulp.task('default', gulp.series('clean', 'build', 'copy'));
