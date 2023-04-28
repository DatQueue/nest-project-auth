import { Column, Entity, PrimaryColumn, PrimaryGeneratedColumn } from 'typeorm';

@Entity({name:'users'})
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({name:'firstname'})
  firstName: string;

  @Column({name:'lastname'})
  lastName: string;

  @Column({name:'email'})
  email: string;

  @Column()
  password: string;

  @Column({ nullable: true })
  currentRefreshToken: string;

  @Column({ type: 'date', nullable: true })
  currentRefreshTokenExp: string;
}
