"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 9:
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
exports.UsersService = void 0;
const common_1 = __webpack_require__(6);
const bcrypt = __webpack_require__(10);
const users_repository_1 = __webpack_require__(11);
let UsersService = class UsersService {
    constructor(userRepository) {
        this.userRepository = userRepository;
    }
    async createUser(newUser) {
        const userFind = await this.userRepository.findOne({
            where: {
                email: newUser.email,
            }
        });
        if (userFind) {
            throw new common_1.HttpException('UserEmail already used!', common_1.HttpStatus.BAD_REQUEST);
        }
        const saltOrRounds = 12;
        const hashedPassword = await this.hashPassword(newUser.password, saltOrRounds);
        return this.userRepository.save(Object.assign(Object.assign({}, newUser), { password: hashedPassword, confirmPassword: hashedPassword }));
    }
    async hashPassword(password, saltOrRounds) {
        return bcrypt.hash(password, saltOrRounds);
    }
    async findUserByEmail(email) {
        return await this.userRepository.findOne({
            where: {
                email: email,
            }
        });
    }
    async findUserById(id) {
        return await this.userRepository.findOne({
            where: {
                id: id
            },
        });
    }
    async updateUserInfo(id, data) {
        const user = await this.findUserById(id);
        if (!user) {
            throw new common_1.NotFoundException('해당 id의 유저 정보는 존재하지 않습니다.');
        }
        const findEmail = await this.findUserByEmail(data.email);
        if (findEmail && findEmail.id !== user.id) {
            throw new common_1.HttpException('Username already used!', common_1.HttpStatus.BAD_GATEWAY);
        }
        await this.userRepository.update(id, data);
        const updatedUser = await this.userRepository.findOne({
            where: {
                id,
            }
        });
        return updatedUser;
    }
    async deleteUser(id) {
        return this.userRepository.delete(id);
    }
    async setCurrentRefreshToken(refreshToken, userId) {
        const saltOrRounds = 10;
        const currentRefreshToken = await bcrypt.hash(refreshToken, saltOrRounds);
        console.log(currentRefreshToken);
        await this.userRepository.update(userId, { currentRefreshToken });
    }
    async getUserIfRefreshTokenMatches(refreshToken, userId) {
        const user = await this.findUserById(userId);
        const isRefreshTokenMatching = await bcrypt.compare(refreshToken, user.currentRefreshToken);
        console.log(isRefreshTokenMatching);
        if (isRefreshTokenMatching) {
            return user;
        }
        else {
            throw new common_1.BadRequestException('Invalid RefreshToken!');
        }
    }
    async getUserByRefreshToken(refreshToken) {
        const user = await this.userRepository.findOne({
            where: {
                currentRefreshToken: refreshToken
            },
        });
        return user;
    }
    getCookiesForLogOut() {
        return [
            'access_token=; HttpOnly; Path=/; Max-Age=0',
            'refresh_token=; HttpOnly; Path=/; Max-Age=0'
        ];
    }
    async removeRefreshToken(userId) {
        return this.userRepository.update(userId, {
            currentRefreshToken: null,
        });
    }
};
UsersService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_repository_1.UsersRepository !== "undefined" && users_repository_1.UsersRepository) === "function" ? _a : Object])
], UsersService);
exports.UsersService = UsersService;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("62c7be91532b803ac86f")
/******/ })();
/******/ 
/******/ }
;