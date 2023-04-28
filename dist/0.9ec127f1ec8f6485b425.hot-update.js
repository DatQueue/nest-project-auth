"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 19:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(6);
const auth_controller_1 = __webpack_require__(20);
const auth_service_1 = __webpack_require__(21);
const passport_1 = __webpack_require__(23);
const jwt_1 = __webpack_require__(50);
const users_module_1 = __webpack_require__(8);
const users_service_1 = __webpack_require__(9);
const typeorm_1 = __webpack_require__(7);
const users_entity_1 = __webpack_require__(14);
const typeorm_ex_decorator_1 = __webpack_require__(18);
const users_repository_1 = __webpack_require__(11);
const jwt_access_strategy_1 = __webpack_require__(113);
const jwt_access_guard_1 = __webpack_require__(121);
const jwt_refresh_strategy_1 = __webpack_require__(125);
const jwt_refresh_guard_1 = __webpack_require__(126);
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([users_entity_1.User]),
            typeorm_ex_decorator_1.TypeOrmExModule.forCustomRepository([users_repository_1.UsersRepository]),
            passport_1.PassportModule.register({}),
            jwt_1.JwtModule.register({}),
            (0, common_1.forwardRef)(() => users_module_1.UsersModule),
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, users_service_1.UsersService, jwt_access_strategy_1.JwtAccessStrategy, jwt_refresh_strategy_1.JwtRefreshStrategy, jwt_access_guard_1.JwtAccessAuthGuard, jwt_refresh_guard_1.JwtRefreshGuard],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("35b12d2fae055e340a67")
/******/ })();
/******/ 
/******/ }
;