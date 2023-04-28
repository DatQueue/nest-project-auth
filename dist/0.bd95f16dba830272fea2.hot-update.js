"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 126:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtRefreshGuard = void 0;
const common_1 = __webpack_require__(6);
const jwt_1 = __webpack_require__(50);
const passport_1 = __webpack_require__(23);
let JwtRefreshGuard = class JwtRefreshGuard extends (0, passport_1.AuthGuard)('jwt-refresh-token') {
    constructor(jwtService) {
        super();
        this.jwtService = jwtService;
    }
    canActivate(context) {
        try {
            const request = context.switchToHttp().getRequest();
            const refresh_token = request.cookies['refresh_token'];
            return this.jwtService.verify(refresh_token);
        }
        catch (err) {
            return false;
        }
    }
};
JwtRefreshGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _a : Object])
], JwtRefreshGuard);
exports.JwtRefreshGuard = JwtRefreshGuard;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("1889aa6f102c29e51285")
/******/ })();
/******/ 
/******/ }
;